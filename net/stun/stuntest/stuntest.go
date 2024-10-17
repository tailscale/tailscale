// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package stuntest provides a STUN test server.
package stuntest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/nettype"
)

type stunStats struct {
	mu sync.Mutex
	// +checklocks:mu
	readIPv4 int
	// +checklocks:mu
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
	go runSTUN(t, pc.(nettype.PacketConn), &stats, doneCh)
	return addr, func() {
		pc.Close()
		<-doneCh
	}
}

func runSTUN(t testing.TB, pc nettype.PacketConn, stats *stunStats, done chan<- struct{}) {
	defer close(done)

	var buf [64 << 10]byte
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				t.Logf("STUN server shutdown")
				return
			}
			continue
		}
		src = netaddr.Unmap(src)
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}

		stats.mu.Lock()
		if src.Addr().Is4() {
			stats.readIPv4++
		} else {
			stats.readIPv6++
		}
		stats.mu.Unlock()

		res := stun.Response(txid, src)
		if _, err := pc.WriteToUDPAddrPort(res, src); err != nil {
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
			Name:       fmt.Sprint(regionID) + "a",
			RegionID:   regionID,
			HostName:   fmt.Sprintf("d%d%s", regionID, tailcfg.DotInvalid),
			IPv4:       ipv4,
			IPv6:       ipv6,
			STUNPort:   port,
			STUNOnly:   true,
			STUNTestIP: host,
		}
		m.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID: regionID,
			Nodes:    []*tailcfg.DERPNode{node},
		}
	}
	return m
}
