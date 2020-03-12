// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stuntest provides a STUN test server.
package stuntest

import (
	"net"
	"strings"
	"sync"
	"testing"

	"tailscale.com/stun"
)

type stunStats struct {
	mu       sync.Mutex
	readIPv4 int
	readIPv6 int
}

func Serve(t *testing.T) (addr string, cleanupFn func()) {
	t.Helper()

	// TODO(crawshaw): use stats to test re-STUN logic
	var stats stunStats

	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to open STUN listener: %v", err)
	}

	stunAddr := pc.LocalAddr().String()
	stunAddr = strings.Replace(stunAddr, "0.0.0.0:", "127.0.0.1:", 1)

	doneCh := make(chan struct{})
	go runSTUN(t, pc, &stats, doneCh)
	return stunAddr, func() {
		pc.Close()
		<-doneCh
	}
}

func runSTUN(t *testing.T, pc net.PacketConn, stats *stunStats, done chan<- struct{}) {
	defer close(done)

	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				t.Logf("STUN server shutdown")
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
			t.Logf("STUN server write failed: %v", err)
		}
	}
}
