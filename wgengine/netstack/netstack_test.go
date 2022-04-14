// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstack

import (
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"inet.af/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

// TestInjectInboundLeak tests that injectInbound doesn't leak memory.
// See https://github.com/tailscale/tailscale/issues/3762
func TestInjectInboundLeak(t *testing.T) {
	tunDev := tstun.NewFake()
	dialer := new(tsdial.Dialer)
	logf := func(format string, args ...any) {
		if !t.Failed() {
			t.Logf(format, args...)
		}
	}
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:    tunDev,
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ig, ok := eng.(wgengine.InternalsGetter)
	if !ok {
		t.Fatal("not an InternalsGetter")
	}
	tunWrap, magicSock, d, ok := ig.GetInternals()
	if !ok {
		t.Fatal("failed to get internals")
	}

	ns, err := Create(logf, tunWrap, eng, magicSock, dialer, d)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.ProcessLocalIPs = true
	if err := ns.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ns.atomicIsLocalIPFunc.Store(func(netaddr.IP) bool { return true })

	pkt := &packet.Parsed{}
	const N = 10_000
	ms0 := getMemStats()
	for i := 0; i < N; i++ {
		outcome := ns.injectInbound(pkt, tunWrap)
		if outcome != filter.DropSilently {
			t.Fatalf("got outcome %v; want DropSilently", outcome)
		}
	}
	ms1 := getMemStats()
	if grew := int64(ms1.HeapObjects) - int64(ms0.HeapObjects); grew >= N {
		t.Fatalf("grew by %v (which is too much and >= the %v packets we sent)", grew, N)
	}
}

func getMemStats() (ms runtime.MemStats) {
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return
}

func TestNetstackLeakMode(t *testing.T) {
	// See the comments in init(), and/or in issue #4309.
	// Influenced by an envknob that may be useful in tests, so just check that
	// it's not the oddly behaving zero value.
	if refs.GetLeakMode() == 0 {
		t.Fatalf("refs.leakMode is 0, want a non-zero value")
	}
}
