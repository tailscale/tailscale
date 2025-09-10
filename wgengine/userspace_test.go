// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"testing"

	"go4.org/mem"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
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

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

func TestUserspaceEngineReconfig(t *testing.T) {
	bus := eventbustest.NewBus(t)

	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
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
			Peers: nodeViews([]*tailcfg.Node{
				{
					ID:  1,
					Key: nkFromHex(nodeHex),
				},
			}),
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
		err = e.Reconfig(cfg, routerCfg, &dns.Config{})
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
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/2855")
	const defaultPort = 49983

	var knobs controlknobs.Knobs

	bus := eventbustest.NewBus(t)

	// Keep making a wgengine until we find an unused port
	var ue *userspaceEngine
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	for i := range 100 {
		attempt := uint16(defaultPort + i)
		e, err := NewFakeUserspaceEngine(t.Logf, attempt, &knobs, ht, reg, bus)
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
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got != startingPort {
		t.Errorf("no debug setting changed local port to %d from %d", got, startingPort)
	}

	knobs.RandomizeClientPort.Store(true)
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got == startingPort {
		t.Errorf("debug setting did not change local port from %d", startingPort)
	}

	lastPort := ue.magicConn.LocalPort()
	knobs.RandomizeClientPort.Store(false)
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if startingPort == defaultPort {
		// Only try this if we managed to bind defaultPort the first time.
		// Otherwise, assume someone else on the computer is using defaultPort
		// and so Reconfig would have caused magicSockt to bind some other port.
		if got := ue.magicConn.LocalPort(); got != defaultPort {
			t.Errorf("debug setting did not change local port from %d to %d", startingPort, defaultPort)
		}
	}
	if got := ue.magicConn.LocalPort(); got == lastPort {
		t.Errorf("Reconfig did not change local port from %d", lastPort)
	}
}

// Test that enabling and disabling peer path MTU discovery works correctly.
func TestUserspaceEnginePeerMTUReconfig(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; peer MTU not supported", runtime.GOOS)
	}

	defer os.Setenv("TS_DEBUG_ENABLE_PMTUD", os.Getenv("TS_DEBUG_ENABLE_PMTUD"))
	envknob.Setenv("TS_DEBUG_ENABLE_PMTUD", "")
	// Turn on debugging to help diagnose problems.
	defer os.Setenv("TS_DEBUG_PMTUD", os.Getenv("TS_DEBUG_PMTUD"))
	envknob.Setenv("TS_DEBUG_PMTUD", "true")

	var knobs controlknobs.Knobs

	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, &knobs, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	ue := e.(*userspaceEngine)

	if ue.magicConn.PeerMTUEnabled() != false {
		t.Error("peer MTU enabled by default, should not be")
	}
	osDefaultDF, err := ue.magicConn.DontFragSetting()
	if err != nil {
		t.Errorf("get don't fragment bit failed: %v", err)
	}
	t.Logf("Info: OS default don't fragment bit(s) setting: %v", osDefaultDF)

	// Build a set of configs to use as we change the peer MTU settings.
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

	tests := []struct {
		desc    string   // test description
		wantP   bool     // desired value of PMTUD setting
		wantDF  bool     // desired value of don't fragment bits
		shouldP opt.Bool // if set, force peer MTU to this value
	}{
		{desc: "after_first_reconfig", wantP: false, wantDF: osDefaultDF, shouldP: ""},
		{desc: "enabling_PMTUD_first_time", wantP: true, wantDF: true, shouldP: "true"},
		{desc: "disabling_PMTUD", wantP: false, wantDF: false, shouldP: "false"},
		{desc: "enabling_PMTUD_second_time", wantP: true, wantDF: true, shouldP: "true"},
		{desc: "returning_to_default_PMTUD", wantP: false, wantDF: false, shouldP: ""},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if v, ok := tt.shouldP.Get(); ok {
				knobs.PeerMTUEnable.Store(v)
			} else {
				knobs.PeerMTUEnable.Store(false)
			}
			if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
				t.Fatal(err)
			}
			if v := ue.magicConn.PeerMTUEnabled(); v != tt.wantP {
				t.Errorf("peer MTU set to %v, want %v", v, tt.wantP)
			}
			if v, err := ue.magicConn.DontFragSetting(); v != tt.wantDF || err != nil {
				t.Errorf("don't fragment bit set to %v, want %v, err %v", v, tt.wantP, err)
			}
		})
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
		for range b.N {
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
		for range b.N {
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
		for range b.N {
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
		for range b.N {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Logf("x = %v", x)
}
