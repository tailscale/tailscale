// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Create two wgengine instances and pass data through them, measuring
// throughput, latency, and packet loss.
package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strconv"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

const PayloadSize = 1000
const ICMPMinSize = 24

var Addr1 = netaddr.MustParseIPPrefix("100.64.1.1/32")
var Addr2 = netaddr.MustParseIPPrefix("100.64.1.2/32")

func main() {
	var logf logger.Logf = log.Printf
	log.SetFlags(0)

	debugMux := newDebugMux()
	go runDebugServer(debugMux, "0.0.0.0:8999")

	mode, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("%q: %v", os.Args[1], err)
	}

	traf := NewTrafficGen(nil)

	// Sample test results below are using GOMAXPROCS=2 (for some
	// tests, including wireguard-go, higher GOMAXPROCS goes slower)
	// on apenwarr's old Linux box:
	//   Intel(R) Core(TM) i7-4785T CPU @ 2.20GHz
	// My 2019 Mac Mini is about 20% faster on most tests.

	switch mode {
	// tx=8786325 rx=8786326 (0 = 0.00% loss) (70768.7 Mbits/sec)
	case 1:
		setupTrivialNoAllocTest(logf, traf)

	// tx=6476293 rx=6476293 (0 = 0.00% loss) (52249.7 Mbits/sec)
	case 2:
		setupTrivialTest(logf, traf)

	// tx=1957974 rx=1958379 (0 = 0.00% loss) (15939.8 Mbits/sec)
	case 11:
		setupBlockingChannelTest(logf, traf)

	// tx=728621 rx=701825 (26620 = 3.65% loss) (5525.2 Mbits/sec)
	// (much faster on macOS??)
	case 12:
		setupNonblockingChannelTest(logf, traf)

	// tx=1024260 rx=941098 (83334 = 8.14% loss) (7516.6 Mbits/sec)
	// (much faster on macOS??)
	case 13:
		setupDoubleChannelTest(logf, traf)

	// tx=265468 rx=263189 (2279 = 0.86% loss) (2162.0 Mbits/sec)
	case 21:
		setupUDPTest(logf, traf)

	// tx=1493580 rx=1493580 (0 = 0.00% loss) (12210.4 Mbits/sec)
	case 31:
		setupBatchTCPTest(logf, traf)

	// tx=134236 rx=133166 (1070 = 0.80% loss) (1088.9 Mbits/sec)
	case 101:
		setupWGTest(nil, logf, traf, Addr1, Addr2)

	default:
		log.Fatalf("provide a valid test number (0..n)")
	}

	logf("initialized ok.")
	traf.Start(Addr1.IP(), Addr2.IP(), PayloadSize+ICMPMinSize, 0)

	var cur, prev Snapshot
	var pps int64
	i := 0
	for {
		i += 1
		time.Sleep(10 * time.Millisecond)

		if (i % 100) == 0 {
			prev = cur
			cur = traf.Snap()
			d := cur.Sub(prev)

			if prev.WhenNsec == 0 {
				logf("tx=%-6d rx=%-6d", d.TxPackets, d.RxPackets)
			} else {
				logf("%v @%7d pkt/s", d, pps)
			}
		}

		pps = traf.Adjust()
	}
}

func newDebugMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func runDebugServer(mux *http.ServeMux, addr string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// The absolute minimal test of the traffic generator: have it fill
// a packet buffer, then absorb it again. Zero packet loss.
func setupTrivialNoAllocTest(logf logger.Logf, traf *TrafficGen) {
	go func() {
		b := make([]byte, 1600)
		for {
			n := traf.Generate(b, 16)
			if n == 0 {
				break
			}
			traf.GotPacket(b[0:n+16], 16)
		}
	}()
}

// Almost the same, but this time allocate a fresh buffer each time
// through the loop. Still zero packet loss. Runs about 2/3 as fast for me.
func setupTrivialTest(logf logger.Logf, traf *TrafficGen) {
	go func() {
		for {
			b := make([]byte, 1600)
			n := traf.Generate(b, 16)
			if n == 0 {
				break
			}
			traf.GotPacket(b[0:n+16], 16)
		}
	}()
}

// Pass packets through a blocking channel between sender and receiver.
// Still zero packet loss since the sender stops when the channel is full.
// Max speed depends on channel length (I'm not sure why).
func setupBlockingChannelTest(logf logger.Logf, traf *TrafficGen) {
	ch := make(chan []byte, 1000)

	go func() {
		// transmitter
		for {
			b := make([]byte, 1600)
			n := traf.Generate(b, 16)
			if n == 0 {
				close(ch)
				break
			}
			ch <- b[0 : n+16]
		}
	}()

	go func() {
		// receiver
		for b := range ch {
			traf.GotPacket(b, 16)
		}
	}()
}

// Same as setupBlockingChannelTest, but now we drop packets whenever the
// channel is full. Max speed is about the same as the above test, but
// now with nonzero packet loss.
func setupNonblockingChannelTest(logf logger.Logf, traf *TrafficGen) {
	ch := make(chan []byte, 1000)

	go func() {
		// transmitter
		for {
			b := make([]byte, 1600)
			n := traf.Generate(b, 16)
			if n == 0 {
				close(ch)
				break
			}
			select {
			case ch <- b[0 : n+16]:
			default:
			}
		}
	}()

	go func() {
		// receiver
		for b := range ch {
			traf.GotPacket(b, 16)
		}
	}()
}

// Same as above, but at an intermediate blocking channel and goroutine
// to make things a little more like wireguard-go. Roughly 20% slower than
// the single-channel verison.
func setupDoubleChannelTest(logf logger.Logf, traf *TrafficGen) {
	ch := make(chan []byte, 1000)
	ch2 := make(chan []byte, 1000)

	go func() {
		// transmitter
		for {
			b := make([]byte, 1600)
			n := traf.Generate(b, 16)
			if n == 0 {
				close(ch)
				break
			}
			select {
			case ch <- b[0 : n+16]:
			default:
			}
		}
	}()

	go func() {
		// intermediary
		for b := range ch {
			ch2 <- b
		}
		close(ch2)
	}()

	go func() {
		// receiver
		for b := range ch2 {
			traf.GotPacket(b, 16)
		}
	}()
}

// Instead of a channel, pass packets through a UDP socket.
func setupUDPTest(logf logger.Logf, traf *TrafficGen) {
	la, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}

	s1, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatalf("listen1: %v", err)
	}
	s2, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatalf("listen2: %v", err)
	}

	a2 := s2.LocalAddr()

	// On macOS (but not Linux), you can't transmit to 0.0.0.0:port,
	// which is what returns from .LocalAddr() above. We have to
	// force it to localhost instead.
	a2.(*net.UDPAddr).IP = net.ParseIP("127.0.0.1")

	s1.SetWriteBuffer(1024 * 1024)
	s2.SetReadBuffer(1024 * 1024)

	go func() {
		// transmitter
		b := make([]byte, 1600)
		for {
			n := traf.Generate(b, 16)
			if n == 0 {
				break
			}
			s1.WriteTo(b[16:n+16], a2)
		}
	}()

	go func() {
		// receiver
		b := make([]byte, 1600)
		for traf.Running() {
			// Use ReadFrom instead of Read, to be more like
			// how wireguard-go does it, even though we're not
			// going to actually look at the address.
			n, _, err := s2.ReadFrom(b)
			if err != nil {
				log.Fatalf("s2.Read: %v", err)
			}
			traf.GotPacket(b[:n], 0)
		}
	}()
}

// Instead of a channel, pass packets through a TCP socket.
// TCP is a single stream, so we can amortize one syscall across
// multiple packets. 10x amortization seems to make it go ~10x faster,
// as expected, getting us close to the speed of the channel tests above.
// There's also zero packet loss.
func setupBatchTCPTest(logf logger.Logf, traf *TrafficGen) {
	sl, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s1, err := net.Dial("tcp", sl.Addr().String())
	if err != nil {
		log.Fatalf("dial: %v", err)
	}

	s2, err := sl.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}

	s1.(*net.TCPConn).SetWriteBuffer(1024 * 1024)
	s2.(*net.TCPConn).SetReadBuffer(1024 * 1024)

	ch := make(chan int)

	go func() {
		// transmitter

		bs1 := bufio.NewWriterSize(s1, 1024*1024)

		b := make([]byte, 1600)
		i := 0
		for {
			i += 1
			n := traf.Generate(b, 16)
			if n == 0 {
				break
			}
			if i == 1 {
				ch <- n
			}
			bs1.Write(b[16 : n+16])

			// TODO: this is a pretty half-baked batching
			// function, which we'd never want to employ in
			// a real-life program.
			//
			// In real life, we'd probably want to flush
			// immediately when there are no more packets to
			// generate, and queue up only if we fall behind.
			//
			// In our case however, we just want to see the
			// technical benefits of batching 10 syscalls
			// into 1, so a fixed ratio makes more sense.
			if (i % 10) == 0 {
				bs1.Flush()
			}
		}
	}()

	go func() {
		// receiver

		bs2 := bufio.NewReaderSize(s2, 1024*1024)

		// Find out the packet size (we happen to know they're
		// all the same size)
		packetSize := <-ch

		b := make([]byte, packetSize)
		for traf.Running() {
			// TODO: can't use ReadFrom() here, which is
			// unfair compared to UDP. (ReadFrom for UDP
			// apparently allocates memory per packet, which
			// this test does not.)
			n, err := io.ReadFull(bs2, b)
			if err != nil {
				log.Fatalf("s2.Read: %v", err)
			}
			traf.GotPacket(b[:n], 0)
		}
	}()
}
