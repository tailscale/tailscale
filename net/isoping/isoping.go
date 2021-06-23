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
	"time"
)

type Packet struct {
	Magic      uint32 // Magic number to reject bogus packets
	Id         uint32 // Id is a sequential packet id number
	Txtime     uint32 // Txtime is the transmitter's monotonic time when pkt was sent
	Clockdiff  uint32 // Clockdiff is an estimate of (transmitter's clk) - (receiver's clk)
	UsecPerPkt uint32 // Usec_per_pkt microseconds of delay between packets
	NumLost    uint32 // Num_lost is the number of pkts transmitter expected to get but didn't
	FirstAck   uint32 // First_ack is the starting index in acks[] circular buffer
	Acks       [64]struct {
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
	Rx             Packet       // Rx is a Packet that will be received
	LastAckInfo    string       // LastAckInfo human readable format of latest ack
	ListenAddr     *net.UDPAddr // ListenAddr is the address of the listener
	RemoteAddr     *net.UDPAddr // RemtoteAddr remote UDP address we send to.
	RxAddr         *net.UDPAddr // RxAddr keeps track of what address we are sending to
	LastRxAddr     *net.UDPAddr // LastRxAddr keeps track of what we last used
	Quiet          bool         // Option to show output or not

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
func onePassStddev(sumsq, sum, count int64) float64 {
	numer := (count * sumsq) - (sum * sum)
	denom := count * (count - 1)
	return math.Sqrt(DIV(numer, denom))
}

// UsecMonoTimeNow returns the monotonic number of microseconds since the program started.
func (srv *Isoping) UsecMonoTimeNow() uint64 {
	tn := time.Since(srv.ClockStartTime)
	return uint64(tn.Microseconds())
}

// UsecMonoTime returns the monotonic number of microseconds since the program started, as a uint32.
func (srv *Isoping) UsecMonoTime() uint32 {
	return uint32(srv.UsecMonoTimeNow())
}

// initClock keeps track of when the server/client starts.
// keeps the exact time and we can subtract from the time
// to get monotonicClock values
func (srv *Isoping) initClock() {
	srv.ClockStartTime = time.Now()
}

// initClient sets the Isoping.Conn, to the address string otherwise
// uses [::]:4948 as the default
func (srv *Isoping) initClient(address string) {
	srv.initClock()
	srv.IsServer = false
	udpaddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Println(err)
		addr := DEFAULT_PORT
		udpaddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("Address %v failed to resolve\n", address)
	}

	conn, err := net.DialUDP("udp", nil, udpaddr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.RemoteAddr = udpaddr
	srv.Conn = conn
}

// initServer sets the Conn field of Isoping, for the listener side.
func (srv *Isoping) initServer(port string) {
	srv.initClock()
	srv.IsServer = true
	addr, err := net.ResolveUDPAddr("udp", port)
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

func NewInstance() *Isoping {
	clockStartTime := time.Now()

	packetsPerSec := DEFAULT_PACKETS_PER_SEC
	printsPerSec := -1

	usecPerPkt := int32(1e6 / packetsPerSec)
	usecPerPrint := int32(0)
	if usecPerPrint > 0 {
		usecPerPrint = int32(1e6 / printsPerSec)
	}
	log.Println("UsecPerPkt : ", usecPerPkt)
	log.Println("UsecPerPrint : ", usecPerPrint)

	nextTxId := 1
	nextRxId := 0

	nextRxackId := 0
	startRtxtime := 0
	startRxtime := 0
	lastRxtime := 0

	minCycleRxdiff := 0
	nextCycle := 0
	nextSend := 0
	nextTxackIndex := 0

	LastAckInfo := ""
	inst := &Isoping{
		packetsPerSec:  packetsPerSec,
		printsPerSec:   float64(printsPerSec),
		usecPerPkt:     int32(1e6 / DEFAULT_PACKETS_PER_SEC),
		usecPerPrint:   usecPerPrint,
		nextTxId:       uint32(nextTxId),
		nextRxId:       uint32(nextRxId),
		nextRxackId:    uint32(nextRxackId),
		startRtxtime:   uint32(startRtxtime),
		startRxtime:    uint32(startRxtime),
		lastRxtime:     uint32(lastRxtime),
		minCycleRxdiff: int32(minCycleRxdiff),
		nextCycle:      uint32(nextCycle),
		nextSend:       uint32(nextSend),
		nextTxackIndex: nextTxackIndex,
		Tx:             Packet{},
		Rx:             Packet{},
		LastAckInfo:    LastAckInfo,
		ClockStartTime: clockStartTime,

		latTx:       0,
		latTxMin:    0x7fffffff,
		latTxMax:    0,
		latTxCount:  0,
		latTxSum:    0,
		latTxVarSum: 0,
		latRx:       0,
		latRxMin:    0x7fffffff,
		latRxMax:    0,
		latRxCount:  0,
		latRxSum:    0,
		latRxVarSum: 0,
	}

	// Setup the clock functions after creating the fields
	inst.now = inst.UsecMonoTime()
	inst.lastPrint = inst.now - uint32(inst.usecPerPkt)
	return inst
}

// generateInitialPacket generates the inital packet Tx
func (srv *Isoping) generateInitialPacket() (*bytes.Buffer, error) {
	srv.Tx.Magic = MAGIC
	srv.Tx.Id = srv.nextTxId
	srv.nextTxId++
	srv.Tx.Txtime = srv.nextSend
	srv.Tx.UsecPerPkt = uint32(srv.usecPerPkt)
	srv.Tx.Clockdiff = 0
	if srv.startRtxtime > 0 {
		srv.Rx.Clockdiff = srv.startRtxtime - srv.startRxtime
	}
	srv.Tx.NumLost = srv.numLost
	srv.Tx.FirstAck = uint32(srv.nextTxackIndex)

	// Setup the Tx to be sent from either server of client
	buf := new(bytes.Buffer)
	return buf, binary.Write(buf, binary.BigEndian, srv.Tx)
}

// StartServer starts the Isoping Server with port
// If no port is given, then starts with DEFAULT_PORT
func (srv *Isoping) StartServer(port string) {
	if port != "" {
		srv.initServer(port)
	} else {
		srv.initServer(DEFAULT_PORT)
	}
}

// StartServer starts the Isoping Client with port
// If no port is given, then starts with DEFAULT_PORT
func (srv *Isoping) StartClient(port string) {
	if port != "" {
		srv.initClient(port)
	} else {
		srv.initClient(DEFAULT_PORT)
	}
}
