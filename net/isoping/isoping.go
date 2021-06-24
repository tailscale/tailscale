// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package isoping implements isoping in Go.
package isoping

import (
	"bytes"
	"encoding/binary"
	"log"
	"math"
	"net"
	"reflect"
	"time"
)

type Packet struct {
	Magic        uint32 // Magic number to reject bogus packets
	Id           uint32 // Id is a sequential packet id number
	Txtime       uint32 // Txtime is the transmitter's monotonic time when pkt was sent
	Clockdiff    uint32 // Clockdiff is an estimate of (transmitter's clk) - (receiver's clk)
	Usec_per_pkt uint32 // Usec_per_pkt microseconds of delay between packets
	Num_lost     uint32 // Num_lost is the number of pkts transmitter expected to get but didn't
	First_ack    uint32 // First_ack is the starting index in acks[] circular buffer
	Acks         [64]struct {
		// txtime==0 for empty elements in this array.
		Id     uint32 // Id field from a received packet
		Rxtime uint32 // Rxtime is a receiver's monotonic time when pkt arrived
	}
}

type Isoping struct {
	ClockStartTime time.Time    // ClockStartTime is the time the program starts
	IsServer       bool         // IsServer distinguishes if we are a server or client
	Conn           *net.UDPConn // Conn is either the server or client's connection
	Tx             Packet       // Tx is a Packet that will be sent
	Rx             Packet       // Rx is a Packet that will be sent
	LastAckInfo    string       // LastAckInfo human readable format of latest ack
	ListenAddr     *net.UDPAddr // ListenAddr is the address of the listener
	RemoteAddr     *net.UDPAddr // RemtoteAddr remote UDP address we send to.
	RxAddr         *net.UDPAddr // RxAddr keeps track of what address we are sending to
	LastRxAddr     *net.UDPAddr // LastRxAddr keeps track of what we last used
	Quiet          bool

	printsPerSec   float64
	packetsPerSec  float64
	usecPerPkt     int32
	usecPerPrint   int32
	nextTxId       uint32
	nextRxId       uint32
	nextRxackId    uint32
	startRtxtime   uint32 // remote's txtime at startup
	startRxtime    uint32 // local rxtime at startup
	lastRxtime     uint32 // local rxtime of last received packet
	minCycleRxdiff int32  // smallest packet delay seen this cycle
	nextCycle      uint32 // time when next cycle begins
	now            uint32 // current time
	nextSend       uint32 // time when we'll send next pkt
	numLost        uint32 // number of rx packets not received
	nextTxackIndex int    // next array item to fill in tx.acks
	lastPrint      uint32 // time of last packet printout
	latTx          int64
	latTxMin       int64
	latTxMax       int64
	latTxCount     int64
	latTxSum       int64
	latTxVarSum    int64

	latRx       int64
	latRxMin    int64
	latRxMax    int64
	latRxCount  int64
	latRxSum    int64
	latRxVarSum int64
}

// Incremental standard deviation calculation, without needing to know the
// mean in advance.  See:
// http://mathcentral.uregina.ca/QQ/database/QQ.09.02/carlos1.html
func onepass_stddev(sumsq int64, sum int64, count int64) float64 {
	numer := (count * sumsq) - (sum * sum)
	denom := count * (count - 1)
	return math.Sqrt(DIV(numer, denom))
}

// ustimenow subtracts the time since the program started and returns it
func (srv *Isoping) ustimenow() uint64 {
	tn := time.Since(srv.ClockStartTime)
	return uint64(tn.Microseconds())
}

// Ustime casts the result of ustimenow to uint32 and returns it
func (srv *Isoping) Ustime() uint32 {
	return uint32(srv.ustimenow())
}

// initClock keeps track of when the server/client starts.
// keeps the exact time and we can subtract from the time
// to get monotonicClock values
func (srv *Isoping) initClock() {
	srv.ClockStartTime = time.Now()
}

// initClient sets the Isoping.Conn, to the address string otherwise
// uses [::]:4948 as the default
func (srv *Isoping) initClient(addressString string) {
	srv.initClock()
	srv.IsServer = false
	udpaddr, err := net.ResolveUDPAddr("udp6", addressString)
	if err != nil {
		log.Println(err)
		addr := "[::]" + SERVER_PORT
		udpaddr, err = net.ResolveUDPAddr("udp6", addr)
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("Address %v failed to resolve, using %v instead\n", addressString, udpaddr)
	}

	conn, err := net.DialUDP("udp6", nil, udpaddr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.RemoteAddr = udpaddr
	srv.Conn = conn
}

// initServer sets the Conn field of Isoping, for the listener side.
func (srv *Isoping) initServer() {
	srv.initClock()
	srv.IsServer = true
	addr, err := net.ResolveUDPAddr("udp6", SERVER_PORT)
	if err != nil {
		log.Println(err)
		return
	}

	srv.ListenAddr = addr
	srv.Conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("%v\n", err)
		return
	}
}

// initVars initializes a lot of the necessary variables for the calculation
func (srv *Isoping) initVars() {
	srv.packetsPerSec = DEFAULT_PACKETS_PER_SEC
	srv.printsPerSec = -1

	srv.usecPerPkt = int32(1e6 / srv.packetsPerSec)
	srv.usecPerPrint = 0
	if srv.usecPerPrint > 0 {
		srv.usecPerPrint = int32(1e6 / srv.printsPerSec)
	}
	log.Println("UsecPerPkt : ", srv.usecPerPkt)
	log.Println("UsecPerPrint : ", srv.usecPerPrint)

	srv.nextTxId = 1
	srv.nextRxId = 0

	srv.nextRxackId = 0
	srv.startRtxtime = 0
	srv.startRxtime = 0
	srv.lastRxtime = 0

	srv.minCycleRxdiff = 0
	srv.nextCycle = 0
	srv.now = srv.Ustime()
	srv.nextSend = 0
	srv.nextTxackIndex = 0
	srv.Tx = Packet{}
	srv.Rx = Packet{}

	srv.LastAckInfo = ""
	srv.lastPrint = srv.now - uint32(srv.usecPerPkt)
	srv.latTx, srv.latTxMin, srv.latTxMax = 0, 0x7fffffff, 0
	srv.latTxCount, srv.latTxMin, srv.latTxVarSum = 0, 0, 0

	srv.latRx, srv.latRxMin, srv.latRxMax = 0, 0x7fffffff, 0
	srv.latRxCount, srv.latRxMin, srv.latRxVarSum = 0, 0, 0
}

// generateInitialPacket generates the inital packet Tx
func (srv *Isoping) generateInitialPacket() (*bytes.Buffer, error) {
	srv.Tx.Magic = MAGIC
	srv.Tx.Id = srv.nextTxId
	srv.nextTxId++
	srv.Tx.Txtime = srv.nextSend
	srv.Tx.Usec_per_pkt = uint32(srv.usecPerPkt)
	srv.Tx.Clockdiff = 0
	if srv.startRtxtime > 0 {
		srv.Rx.Clockdiff = srv.startRtxtime - srv.startRxtime
	}
	srv.Tx.Num_lost = srv.numLost
	srv.Tx.First_ack = uint32(srv.nextTxackIndex)

	// Setup the Tx to be sent from either server of client
	buf := new(bytes.Buffer)
	return buf, binary.Write(buf, binary.BigEndian, srv.Tx)
}

// Start starts the Isoping instance, if an address is passed a client is started
// with that address, otherwise a server will start.
func (srv *Isoping) Start(address ...string) {
	if len(address) > 0 {
		srv.initClient(address[0])
	} else {
		srv.initServer()
	}
	srv.initVars()
}

func (srv *Isoping) MainLoop() {
	for {
		log.Println("Action")
		srv.now = srv.Ustime()
		log.Printf("%d - %d = %d\n", srv.now, srv.nextSend, DIFF(srv.now, srv.nextSend))
		if srv.RemoteAddr != nil && DIFF(srv.now, srv.nextSend) >= 0 {
			// Check if it is a server or not
			buf, err := srv.generateInitialPacket()
			if err != nil {
				log.Println(err)
				continue
			}
			if srv.IsServer {
				log.Println("Isoping Server Found.")
				// Attempt to send the srv.Tx to the client
				n, err := srv.Conn.WriteToUDP(buf.Bytes(), srv.RemoteAddr)
				if err != nil {
					log.Println(err)
				}
				log.Printf("Sent %v bytes to %v\n", n, srv.RemoteAddr)
			} else {
				log.Println("Isoping Client Found.")
				n, err := srv.Conn.Write(buf.Bytes())
				if err != nil {
					log.Println(err)
				}
				log.Printf("Sent %v bytes to %v\n", n, srv.RemoteAddr)
			}

			if srv.IsServer && DIFF(srv.now, srv.lastRxtime) > 60*1000*1000 {
				log.Println("client disconnected")
				srv.RemoteAddr = nil
			}
			srv.nextSend += uint32(srv.usecPerPkt)
		}

		// handle incoming packet
		log.Println("BEFORE READ")
		p := make([]byte, binary.Size(srv.Rx))
		got, rxaddr, err := srv.Conn.ReadFromUDP(p)
		if err != nil {
			log.Println(err)
			continue
		}
		srv.RxAddr = rxaddr
		log.Println("AFTER READ")
		// Copy the data received into the Rx struct.
		buffer := bytes.NewBuffer(p)
		err = binary.Read(buffer, binary.BigEndian, &srv.Rx)
		if err != nil {
			log.Println(err)
			continue
		}

		if got != binary.Size(srv.Rx) || srv.Rx.Magic != MAGIC {
			log.Println("received Rx is not proper")
			continue
		}

		log.Printf("%+v\n", srv.Rx)

		if srv.IsServer {
			if srv.RemoteAddr == nil || !reflect.DeepEqual(srv.RxAddr, srv.LastRxAddr) {
				log.Printf("new client connected %v\n", srv.RxAddr)
			}
			srv.LastRxAddr = srv.RxAddr
			log.Println(srv.LastRxAddr, srv.RxAddr)
			srv.RemoteAddr = srv.LastRxAddr
			srv.nextSend = srv.now + 10*1000
			srv.nextTxId = 1

			srv.nextRxId, srv.nextRxackId = 0, 0
			srv.startRtxtime, srv.startRxtime = 0, 0
			srv.numLost = 0
			srv.nextTxackIndex = 0
			srv.usecPerPkt = int32(srv.Rx.Usec_per_pkt)
			// memset Tx to reset it.
			srv.Tx = Packet{}
			log.Println("Remote address for server : ", srv.RemoteAddr)
		}

		txtime := srv.Rx.Txtime
		rxtime := srv.now
		id := srv.Rx.Id

		if srv.nextRxId == 0 {
			log.Println(txtime, id)
			srv.startRtxtime = txtime - id*uint32(srv.usecPerPkt)

			srv.startRxtime = rxtime - id*uint32(srv.usecPerPkt)

			srv.minCycleRxdiff = 0
			srv.nextRxId = id
			srv.nextCycle = srv.now + USEC_PER_CYCLE
		}
		log.Println("tmpdiff break")
		tmpdiff := DIFF(id, srv.nextRxId)
		if tmpdiff > 0 {
			log.Printf("lost %v  expected=%v  got=%v\n",
				int64(tmpdiff), int64(srv.nextRxId), int64(id))
			srv.numLost += uint32(tmpdiff)
			srv.nextRxId += uint32(tmpdiff) + 1
		} else if tmpdiff == 0 {
			log.Println("tmpdiff == 0 -> nextRxId ++")
			srv.nextRxId++
		} else if tmpdiff < 0 {
			log.Println("out-of-order packets? %ld\n", int64(tmpdiff))
		}

		tmpdiff = DIFF(rxtime, srv.startRxtime+id*uint32(srv.usecPerPkt))
		if tmpdiff < -20 {
			log.Printf("time paradox: backsliding start by %v usec\n", tmpdiff)
			srv.startRxtime = rxtime - id*uint32(srv.usecPerPkt)
		}
		rxdiff := DIFF(rxtime, srv.startRxtime+id*uint32(srv.usecPerPkt))

		clockdiff := DIFF(srv.startRxtime, srv.startRtxtime)
		rtt := clockdiff + int32(srv.Rx.Clockdiff)

		// Casting issue here may exist
		// offset := DIFF(uint32(clockdiff), uint32(rtt/2))
		if srv.Rx.Clockdiff == 0 {
			srv.lastPrint = srv.now - uint32(srv.usecPerPrint) + 1
		} else {
			srv.latRxCount++
			srv.latRx = int64(rxdiff) + int64(rtt/2)
			// Take the mins and maxes.
			if srv.latRxMin > srv.latRx {
				srv.latRxMin = srv.latRx
			}

			if srv.latRxMax < srv.latRx {
				srv.latRxMax = srv.latRx
			}

			srv.latRxSum += srv.latRx
			srv.latRxVarSum += srv.latRx * srv.latRx
		}
		okToPrint := !srv.Quiet && DIFF(srv.now, srv.lastPrint) >= srv.usecPerPrint
		log.Println("OKTOPRINT : ", okToPrint)

	}
}
