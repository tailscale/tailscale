// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"go4.org/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestNoteReceiveActivity(t *testing.T) {
	now := mono.Time(123456)
	var logBuf tstest.MemLogger

	confc := make(chan bool, 1)
	gotConf := func() bool {
		select {
		case <-confc:
			return true
		default:
			return false
		}
	}
	e := &userspaceEngine{
		timeNow:               func() mono.Time { return now },
		recvActivityAt:        map[key.NodePublic]mono.Time{},
		logf:                  logBuf.Logf,
		tundev:                new(tstun.Wrapper),
		testMaybeReconfigHook: func() { confc <- true },
		trimmedNodes:          map[key.NodePublic]bool{},
	}
	ra := e.recvActivityAt

	nk := key.NewNode().Public()

	// Activity on an untracked key should do nothing.
	e.noteRecvActivity(nk)
	if len(ra) != 0 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 0", len(ra))
	}
	if logBuf.Len() != 0 {
		t.Fatalf("unexpected log write (and thus activity): %s", logBuf.Bytes())
	}

	// Now track it, but don't mark it trimmed, so shouldn't update.
	ra[nk] = 0
	e.noteRecvActivity(nk)
	if len(ra) != 1 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 1", len(ra))
	}
	if got := ra[nk]; got != now {
		t.Fatalf("time in map = %v; want %v", got, now)
	}
	if gotConf() {
		t.Fatalf("unexpected reconfig")
	}

	// Now mark it trimmed and expect an update.
	e.trimmedNodes[nk] = true
	e.noteRecvActivity(nk)
	if len(ra) != 1 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 1", len(ra))
	}
	if got := ra[nk]; got != now {
		t.Fatalf("time in map = %v; want %v", got, now)
	}
	if !gotConf() {
		t.Fatalf("didn't get expected reconfig")
	}
}

func TestUserspaceEngineReconfig(t *testing.T) {
	e, err := NewFakeUserspaceEngine(t.Logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	ue := e.(*userspaceEngine)

	routerCfg := &router.Config{}

	for _, nodeHex := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		nm := &netmap.NetworkMap{
			Peers: []*tailcfg.Node{
				{
					Key: nkFromHex(nodeHex),
				},
			},
		}
		nk, err := key.ParseNodePublicUntyped(mem.S(nodeHex))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &wgcfg.Config{
			Peers: []wgcfg.Peer{
				{
					PublicKey: nk,
					AllowedIPs: []netip.Prefix{
						netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32),
					},
				},
			},
		}

		e.SetNetworkMap(nm)
		err = e.Reconfig(cfg, routerCfg, &dns.Config{}, nil)
		if err != nil {
			t.Fatal(err)
		}

		wantRecvAt := map[key.NodePublic]mono.Time{
			nkFromHex(nodeHex): 0,
		}
		if got := ue.recvActivityAt; !reflect.DeepEqual(got, wantRecvAt) {
			t.Errorf("wrong recvActivityAt\n got: %v\nwant: %v\n", got, wantRecvAt)
		}

		wantTrimmedNodes := map[key.NodePublic]bool{
			nkFromHex(nodeHex): true,
		}
		if got := ue.trimmedNodes; !reflect.DeepEqual(got, wantTrimmedNodes) {
			t.Errorf("wrong wantTrimmedNodes\n got: %v\nwant: %v\n", got, wantTrimmedNodes)
		}
	}
}

func TestUserspaceEnginePortReconfig(t *testing.T) {
	const defaultPort = 49983
	// Keep making a wgengine until we find an unused port
	var ue *userspaceEngine
	for i := 0; i < 100; i++ {
		attempt := uint16(defaultPort + i)
		e, err := NewFakeUserspaceEngine(t.Logf, attempt)
		if err != nil {
			t.Fatal(err)
		}
		ue = e.(*userspaceEngine)
		if ue.magicConn.LocalPort() == attempt {
			break
		}
		ue.Close()
		ue = nil
	}
	if ue == nil {
		t.Fatal("could not create a wgengine with a specific port")
	}
	t.Cleanup(ue.Close)

	startingPort := ue.magicConn.LocalPort()
	nodeKey, err := key.ParseNodePublicUntyped(mem.S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &wgcfg.Config{
		Peers: []wgcfg.Peer{
			{
				PublicKey: nodeKey,
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32),
				},
			},
		},
	}
	routerCfg := &router.Config{}
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got != startingPort {
		t.Errorf("no debug setting changed local port to %d from %d", got, startingPort)
	}
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}, &tailcfg.Debug{RandomizeClientPort: true}); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got == startingPort {
		t.Errorf("debug setting did not change local port from %d", startingPort)
	}

	lastPort := ue.magicConn.LocalPort()
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}, nil); err != nil {
		t.Fatal(err)
	}
	if startingPort == defaultPort {
		// Only try this if we managed to bind defaultPort the first time.
		// Otherwise, assume someone else on the computer is using defaultPort
		// and so Reconfig would have caused magicSocket to bind some other port.
		if got := ue.magicConn.LocalPort(); got != defaultPort {
			t.Errorf("debug setting did not change local port from %d to %d", startingPort, defaultPort)
		}
	}
	if got := ue.magicConn.LocalPort(); got == lastPort {
		t.Errorf("Reconfig did not change local port from %d", lastPort)
	}
}

func nkFromHex(hex string) key.NodePublic {
	if len(hex) != 64 {
		panic(fmt.Sprintf("%q is len %d; want 64", hex, len(hex)))
	}
	k, err := key.ParseNodePublicUntyped(mem.S(hex[:64]))
	if err != nil {
		panic(fmt.Sprintf("%q is not hex: %v", hex, err))
	}
	return k
}

// an experiment to see if genLocalAddrFunc was worth it. As of Go
// 1.16, it still very much is. (30-40x faster)
func BenchmarkGenLocalAddrFunc(b *testing.B) {
	la1 := netip.MustParseAddr("1.2.3.4")
	la2 := netip.MustParseAddr("::4")
	lanot := netip.MustParseAddr("5.5.5.5")
	var x bool
	b.Run("map1", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		m := map[netip.Addr]bool{
			la1: true,
		}
		for i := 0; i < b.N; i++ {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("map2", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		m := map[netip.Addr]bool{
			la1: true,
			la2: true,
		}
		for i := 0; i < b.N; i++ {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("or1", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		f := func(t netip.Addr) bool {
			return t == la1
		}
		for i := 0; i < b.N; i++ {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Run("or2", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		f := func(t netip.Addr) bool {
			return t == la1 || t == la2
		}
		for i := 0; i < b.N; i++ {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Logf("x = %v", x)
}
