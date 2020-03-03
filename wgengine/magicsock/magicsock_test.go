// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/stun"
)

func TestListen(t *testing.T) {
	epCh := make(chan string, 16)
	epFunc := func(endpoints []string) {
		for _, ep := range endpoints {
			epCh <- ep
		}
	}

	stunAddr, stunCleanupFn := serveSTUN(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := Listen(Options{
		Port:          port,
		STUN:          []string{stunAddr.String()},
		EndpointsFunc: epFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		var pkt [64 << 10]byte
		for {
			_, _, _, err := conn.ReceiveIPv4(pkt[:])
			if err != nil {
				return
			}
		}
	}()

	timeout := time.After(10 * time.Second)
	var endpoints []string
	suffix := fmt.Sprintf(":%d", port)
collectEndpoints:
	for {
		select {
		case ep := <-epCh:
			endpoints = append(endpoints, ep)
			if strings.HasSuffix(ep, suffix) {
				break collectEndpoints
			}
		case <-timeout:
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestDerpIPConstant(t *testing.T) {
	if DerpMagicIP != derpMagicIP.String() {
		t.Errorf("str %q != IP %v", DerpMagicIP, derpMagicIP)
	}
	if len(derpMagicIP) != 4 {
		t.Errorf("derpMagicIP is len %d; want 4", len(derpMagicIP))
	}
}

func TestPickDERPFallback(t *testing.T) {
	if len(derpNodeID) == 0 {
		t.Fatal("no DERP nodes registered; this test needs an update after DERP node runtime discovery")
	}

	c := new(Conn)
	a := c.pickDERPFallback()
	if a == 0 {
		t.Fatalf("pickDERPFallback returned 0")
	}

	// Test that it's consistent.
	for i := 0; i < 50; i++ {
		b := c.pickDERPFallback()
		if a != b {
			t.Fatalf("got inconsistent %d vs %d values", a, b)
		}
	}

	// Test that that the pointer value of c is blended in and
	// distribution over nodes works.
	got := map[int]int{}
	for i := 0; i < 50; i++ {
		c = new(Conn)
		got[c.pickDERPFallback()]++
	}
	t.Logf("distribution: %v", got)
	if len(got) < 2 {
		t.Errorf("expected more than 1 node; got %v", got)
	}

	// Test that stickiness works.
	const someNode = 123456
	c.myDerp = someNode
	if got := c.pickDERPFallback(); got != someNode {
		t.Errorf("not sticky: got %v; want %v", got, someNode)
	}
}

type stunStats struct {
	mu       sync.Mutex
	readIPv4 int
	readIPv6 int
}

func serveSTUN(t *testing.T) (addr net.Addr, cleanupFn func()) {
	t.Helper()

	// TODO(crawshaw): use stats to test re-STUN logic
	var stats stunStats

	pc, err := net.ListenPacket("udp4", ":3478")
	if err != nil {
		t.Fatalf("failed to open STUN listener: %v", err)
	}

	go runSTUN(pc, &stats)
	return pc.LocalAddr(), func() { pc.Close() }
}

func runSTUN(pc net.PacketConn, stats *stunStats) {
	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				log.Printf("STUN server shutdown")
				return
			}
			continue
		}
		ua := addr.(*net.UDPAddr)
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}

		stats.mu.Lock()
		if ua.IP.To4() != nil {
			stats.readIPv4++
		} else {
			stats.readIPv6++
		}
		stats.mu.Unlock()

		res := stun.Response(txid, ua.IP, uint16(ua.Port))
		if _, err := pc.WriteTo(res, addr); err != nil {
			log.Printf("STUN server write failed: %v", err)
		}
	}
}
