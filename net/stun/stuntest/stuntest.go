// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stuntest provides a STUN test server.
package stuntest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/nettype"
)

type stunStats struct {
	mu       sync.Mutex
	readIPv4 int
	readIPv6 int
}

func Serve(t testing.TB) (addr *net.UDPAddr, cleanupFn func()) {
	return ServeWithPacketListener(t, nettype.Std{})
}

func ServeWithPacketListener(t testing.TB, ln nettype.PacketListener) (addr *net.UDPAddr, cleanupFn func()) {
	t.Helper()

	// TODO(crawshaw): use stats to test re-STUN logic
	var stats stunStats

	pc, err := ln.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatalf("failed to open STUN listener: %v", err)
	}
	addr = pc.LocalAddr().(*net.UDPAddr)
	if len(addr.IP) == 0 || addr.IP.IsUnspecified() {
		addr.IP = net.ParseIP("127.0.0.1")
	}
	doneCh := make(chan struct{})
	go runSTUN(t, pc, &stats, doneCh)
	return addr, func() {
		pc.Close()
		<-doneCh
	}
}

func runSTUN(t testing.TB, pc net.PacketConn, stats *stunStats, done chan<- struct{}) {
	defer close(done)

	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			// TODO: when we switch to Go 1.16, replace this with errors.Is(err, net.ErrClosed)
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

		nia, _ := netip.AddrFromSlice(ua.IP)
		res := stun.Response(txid, netip.AddrPortFrom(nia, uint16(ua.Port)))
		if _, err := pc.WriteTo(res, addr); err != nil {
			t.Logf("STUN server write failed: %v", err)
		}
	}
}

func DERPMapOf(stun ...string) *tailcfg.DERPMap {
	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{},
	}
	for i, hostPortStr := range stun {
		regionID := i + 1
		host, portStr, err := net.SplitHostPort(hostPortStr)
		if err != nil {
			panic(fmt.Sprintf("bogus STUN hostport: %q", hostPortStr))
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			panic(fmt.Sprintf("bogus port %q in %q", portStr, hostPortStr))
		}
		var ipv4, ipv6 string
		ip, err := netip.ParseAddr(host)
		if err != nil {
			panic(fmt.Sprintf("bogus non-IP STUN host %q in %q", host, hostPortStr))
		}
		if ip.Is4() {
			ipv4 = host
			ipv6 = "none"
		}
		if ip.Is6() {
			ipv6 = host
			ipv4 = "none"
		}
		node := &tailcfg.DERPNode{
			Name:     fmt.Sprint(regionID) + "a",
			RegionID: regionID,
			HostName: fmt.Sprintf("d%d%s", regionID, tailcfg.DotInvalid),
			IPv4:     ipv4,
			IPv6:     ipv6,
			STUNPort: port,
			STUNOnly: true,
		}
		m.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID: regionID,
			Nodes:    []*tailcfg.DERPNode{node},
		}
	}
	return m
}
