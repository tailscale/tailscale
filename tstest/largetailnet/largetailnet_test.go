// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package largetailnet_test

import (
	"context"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/largetailnet"
	"tailscale.com/types/logger"
)

// tsnet.Server.Up handles the wait-for-ipn.Running step itself: it
// subscribes to the IPN bus with NotifyInitialState and blocks until State
// reaches ipn.Running, which by definition means a netmap has been applied.
// We don't redo that work here.

var (
	flagActuallyTest = flag.Bool("actually-test-giant-tailnet", false,
		"if set, run the BenchmarkGiantTailnet* benchmarks; otherwise they are skipped")
	flagN = flag.Int("giant-tailnet-n", 250_000,
		"size of the initial netmap (peer count) for BenchmarkGiantTailnet*")
	flagBenchVerbose = flag.Bool("giant-tailnet-verbose", false,
		"if set, log tsnet output and DERP setup to stderr")
)

// BenchmarkGiantTailnet measures the per-delta CPU cost of a tailnet client
// processing peer-add/peer-remove deltas in steady state, with no IPN bus
// subscribers attached. This represents the headless-tailscaled workload
// (Linux subnet routers, container sidecars, ...) where the LocalBackend
// does not pay for fanning Notify.NetMap out to GUI watchers.
//
// Use [BenchmarkGiantTailnetBusWatcher] for the GUI-client workload.
//
// The benchmark is opt-in via --actually-test-giant-tailnet.
func BenchmarkGiantTailnet(b *testing.B) {
	if !*flagActuallyTest {
		b.Skip("set --actually-test-giant-tailnet to run this benchmark")
	}
	benchGiantTailnet(b, false)
}

// BenchmarkGiantTailnetBusWatcher is like [BenchmarkGiantTailnet] but
// attaches one [local.Client.WatchIPNBus] subscriber for the duration of the
// benchmark. The Notify-fan-out cost (notably Notify.NetMap encoding to
// every watcher on every full-rebuild path) is therefore included in the
// per-delta measurement, which approximates the GUI-client workload.
//
// The benchmark is opt-in via --actually-test-giant-tailnet.
func BenchmarkGiantTailnetBusWatcher(b *testing.B) {
	if !*flagActuallyTest {
		b.Skip("set --actually-test-giant-tailnet to run this benchmark")
	}
	benchGiantTailnet(b, true)
}

// benchGiantTailnet is the shared body of the BenchmarkGiantTailnet*
// benchmarks. Setup is entirely in-process: a [testcontrol.Server] hosts
// the control plane, a [tsnet.Server] hosts the client, and a
// [largetailnet.Streamer] hijacks the map long-poll to drive an exact
// MapResponse sequence.
//
// Each loop iteration sends one [tailcfg.MapResponse] with PeersChanged
// (a fresh peer) and PeersRemoved (the previous fresh peer), then waits
// for the client to apply it. Net peer count stays at flagN throughout the
// loop.
//
// The wait mechanism differs by variant:
//
//   - busWatcher=false: block on a channel returned by
//     [ipnlocal.LocalBackend.AwaitNodeKeyForTest] (reached via
//     [tsnet.TestHooks]). The channel is closed by LocalBackend the moment
//     the just-added peer's key appears in the netmap, so the wait has zero
//     polling overhead.
//   - busWatcher=true: drain Notify events from the bus subscription, since
//     a Notify firing is exactly the side-effect we want to amortize into
//     the per-delta measurement.
//
// Recommended invocation for profiling on unmodified main:
//
//	go test ./tstest/largetailnet/ -run=^$ \
//	    -bench='BenchmarkGiantTailnet(BusWatcher)?$' \
//	    -benchtime=2000x -timeout=10m \
//	    --actually-test-giant-tailnet \
//	    --giant-tailnet-n=250000 \
//	    -cpuprofile=/tmp/giant.cpu.pprof
func benchGiantTailnet(b *testing.B, busWatcher bool) {
	logf := logger.Discard
	if *flagBenchVerbose {
		logf = b.Logf
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	b.Cleanup(cancel)

	derpMap := integration.RunDERPAndSTUN(b, logf, "127.0.0.1")

	streamer := largetailnet.New(*flagN, derpMap)

	ctrl := &testcontrol.Server{
		DERPMap:      derpMap,
		DNSConfig:    &tailcfg.DNSConfig{},
		AltMapStream: streamer.AltMapStream(),
		Logf:         logf,
	}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	b.Cleanup(ctrl.HTTPTestServer.Close)
	controlURL := ctrl.HTTPTestServer.URL
	b.Logf("testcontrol listening on %s", controlURL)

	tmp := filepath.Join(b.TempDir(), "tsnet")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		b.Fatal(err)
	}

	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   "largetailnet-bench",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logf,
	}
	b.Cleanup(func() { s.Close() })

	// tsnet.Server.Up blocks until the backend reaches Running, which
	// requires the initial flagN-peer MapResponse to have been processed.
	upStart := time.Now()
	if _, err := s.Up(ctx); err != nil {
		b.Fatalf("tsnet.Server.Up: %v", err)
	}
	b.Logf("initial %d-peer netmap processed in %v", *flagN, time.Since(upStart))

	lc, err := s.LocalClient()
	if err != nil {
		b.Fatalf("LocalClient: %v", err)
	}
	lb := tsnet.TestHooks.LocalBackend(s)

	var notifyCh chan struct{}
	if busWatcher {
		bw, err := lc.WatchIPNBus(ctx, 0)
		if err != nil {
			b.Fatalf("WatchIPNBus: %v", err)
		}
		b.Cleanup(func() { bw.Close() })
		notifyCh = make(chan struct{}, 1024)
		go func() {
			for {
				n, err := bw.Next()
				if err != nil {
					return
				}
				if n.NetMap != nil || len(n.PeerChanges) > 0 {
					select {
					case notifyCh <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	var prevAdded *tailcfg.Node
	runtime.GC()

	b.ResetTimer()
	for b.Loop() {
		added := streamer.AllocPeer()
		mr := &tailcfg.MapResponse{
			PeersChanged: []*tailcfg.Node{added},
		}
		if prevAdded != nil {
			mr.PeersRemoved = []tailcfg.NodeID{prevAdded.ID}
		}
		prevAdded = added

		if err := streamer.SendDelta(ctx, mr); err != nil {
			b.Fatalf("SendDelta: %v", err)
		}

		if busWatcher {
			// A Notify firing is itself part of the workload we
			// want to measure on this variant.
			select {
			case <-notifyCh:
			case <-time.After(10 * time.Second):
				b.Fatal("timed out waiting for notify")
			case <-ctx.Done():
				b.Fatalf("ctx done waiting for notify: %v", ctx.Err())
			}
		} else {
			// Block on the LocalBackend's test-only signal that
			// the just-added peer key has landed in the netmap.
			// No polling, no notify fan-out cost.
			select {
			case <-lb.AwaitNodeKeyForTest(added.Key):
			case <-time.After(10 * time.Second):
				b.Fatalf("timed out waiting for node key %v", added.Key)
			case <-ctx.Done():
				b.Fatalf("ctx done waiting for node key: %v", ctx.Err())
			}
		}
	}
}
