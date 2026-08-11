// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package membudget contains memory budget regression tests: it brings up an
// in-process backend (via tsnet) against an in-process fake control server
// with a parameterized number of peers, and asserts that the live (post-GC)
// Go heap stays within budget.
//
// Static binary size/dirty-page budgets are enforced elsewhere (see the iOS
// extension size checks); these tests cover what those cannot: runtime heap
// cost at startup and heap cost proportional to netmap size. On iOS the
// Network Extension has a hard 50 MiB phys_footprint limit (jetsam), so
// regressions here that look small on servers can make large tailnets
// unusable on mobile. For example, a table pre-allocation at extension init
// once cost 15.8 MiB of live heap before any netmap arrived: well below the
// noise floor of any existing test, but ~1/3 of the entire iOS budget.
package membudget

import (
	"context"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	// Match the feature set of shipping clients as closely as possible so
	// that feature init cost is measured. (tsnet by default imports only a
	// subset of features.)
	_ "tailscale.com/feature/condregister"
)

// Budgets, in bytes of live heap (measured after runtime.GC).
//
// These are deliberately generous to avoid flakes from allocator noise and
// unrelated churn; they exist to catch order-of-magnitude regressions of the
// kind that break memory-limited platforms (iOS NetworkExtension: 50 MiB
// phys_footprint for the whole process, of which ~15 MiB is non-heap).
//
// If you trip one of these, either find the regression (see
// http://go/ios-memory or `go tool pprof` the heap) or, if the growth is
// genuinely necessary and accounted for, raise the budget in the same change
// with a justification.
//
// Note that these tests run with TS_DEBUG_WG_BATCH_SIZE=1 (see
// measureNodeCost), so wireguard-go packet-pool memory is measured at its
// mobile configuration, not the Linux server default.
const (
	// startupBudget is the live-heap budget for bringing up a backend
	// connected to a tailnet with zero peers: feature/extension init,
	// engine, netstack, DNS, control client, etc.
	//
	// As of 2026-08 the measured cost is ~1.3 MiB; the budget leaves ~6x
	// headroom for organic growth while still catching multi-MiB
	// regressions (the conn25 flow table pre-allocation this test was
	// written for measured 17 MiB here).
	startupBudget = 8 << 20

	// perPeerBudget is the marginal live-heap budget per netmap peer
	// (magicsock endpoint state, netmap views, filter, routes, ...).
	perPeerBudget = 64 << 10
)

// nPeers is the number of fake peers used to measure marginal per-peer cost.
// Large enough that per-peer cost dominates measurement noise; comparable to
// a large corporate tailnet as seen by one node.
const nPeers = 600

// liveHeap returns the current live heap size, after forcing GC.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC() // run finalizers queued by the first cycle, then collect
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func startControl(t *testing.T, peers int) (controlURL string) {
	t.Helper()
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	for range peers {
		control.AddFakeNode()
	}
	return control.HTTPTestServer.URL
}

// startNode starts a tsnet node against controlURL and waits for it to reach
// Running with its full netmap.
func startNode(t *testing.T, ctx context.Context, controlURL string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "membudget",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
		UserLogf:   logger.Discard,
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// measureNodeCost returns the live heap delta of running one tsnet node
// connected to a control server with the given number of peers.
//
// The fake control server (and DERP) run in the same process; their live
// state is mostly established before the baseline measurement, but some
// cross-talk is unavoidable and is part of why budgets are generous.
func measureNodeCost(t *testing.T, peers int) uint64 {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use the minimum wireguard-go batch size, matching iOS and other
	// memory-constrained platforms (which are what these budgets protect).
	// Without this, on Linux each of wireguard-go's four reader goroutines
	// (three UDP receive paths plus the TUN reader) pins batch-size (128) ×
	// 64 KiB message buffers at startup: ~32 MiB of live heap that exists
	// only in the Linux configuration and would drown out the regressions
	// this test exists to catch.
	t.Setenv("TS_DEBUG_WG_BATCH_SIZE", "1")

	controlURL := startControl(t, peers)
	baseline := liveHeap()
	s := startNode(t, ctx, controlURL)

	// Wait for the netmap to be fully processed and transients to die.
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if st, err := lc.Status(ctx); err != nil {
		t.Fatal(err)
	} else if got := len(st.Peer); got < peers {
		t.Fatalf("status shows %v peers; want at least %v", got, peers)
	}

	after := liveHeap()
	if after < baseline {
		return 0
	}
	return after - baseline
}

func TestBackendStartupMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	cost := measureNodeCost(t, 0)
	t.Logf("live heap cost of backend with 0 peers: %.2f MiB (budget %.2f MiB)",
		float64(cost)/(1<<20), float64(startupBudget)/(1<<20))
	if cost > startupBudget {
		t.Errorf("backend startup live heap %v exceeds budget %v", cost, int(startupBudget))
	}
}

func TestBackendPerPeerMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	base := measureNodeCost(t, 0)
	loaded := measureNodeCost(t, nPeers)
	if loaded < base {
		t.Skipf("measurement noise: %v peers cost (%v) below 0 peers cost (%v)", nPeers, loaded, base)
	}
	perPeer := (loaded - base) / nPeers
	t.Logf("live heap: 0 peers=%.2f MiB, %d peers=%.2f MiB, per peer=%.1f KiB (budget %.1f KiB)",
		float64(base)/(1<<20), nPeers, float64(loaded)/(1<<20),
		float64(perPeer)/(1<<10), float64(perPeerBudget)/(1<<10))
	if perPeer > perPeerBudget {
		t.Errorf("per-peer live heap %v exceeds budget %v", perPeer, int(perPeerBudget))
	}
}
