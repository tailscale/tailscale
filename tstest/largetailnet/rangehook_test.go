// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_rangehook

// This file finds accidentally-O(n) range loops in the netmap delta
// processing path by using the runtime.DidRange hook, a Tailscale-only
// Go toolchain modification that calls a hook func after every range
// loop in the program with the loop's potential and actual iteration
// counts.
//
// How to run this analysis:
//
//  1. Get the modified Go toolchain: the "bradfitz/rangehook" branch of
//     github.com/tailscale/go. As of 2026-07-11 that branch is based on
//     upstream Go at approximately version 1.27rc1; it will need to be
//     rebased onto newer Go releases as this repo's required Go version
//     advances. The toolchain change itself is one commit adding
//     runtime.DidRange (see that commit's message for details on which
//     loops report and which control flow skips the report).
//
//  2. Build it:
//
//     git clone -b bradfitz/rangehook https://github.com/tailscale/go /tmp/rangehook-go
//     cd /tmp/rangehook-go/src && GOTOOLCHAIN=local ./make.bash
//
//  3. Run this test with that toolchain and this file's build tag:
//
//     GOTOOLCHAIN=local /tmp/rangehook-go/bin/go test -tags=ts_rangehook \
//     -run=TestRangeHook ./tstest/largetailnet/ -v
//
//  4. Read the results. The test logs every unique violating range-loop
//     stack with its sample count, and also writes a pprof proto
//     (default /tmp/rangehook.pprof, or set -rangehook-out) for:
//
//     go tool pprof -top /tmp/rangehook.pprof
//
// A loop is a violation if its potential or actual iteration count is
// at least -rangehook-min (default: half of -rangehook-n). With the
// threshold at N/2, a random O(n) scan that stops at a sought item is
// still caught with probability ~1/2 per scan, so over a few hundred
// deltas every such loop shows up with high confidence. A loop firing
// once per delta (a count near -rangehook-deltas) is per-delta O(n)
// work: exactly the thing tailscale/tailscale#12542 wants eliminated.
//
// The stock toolchain cannot compile this file (runtime.DidRange does
// not exist there), which is why it's guarded by the ts_rangehook tag.
package largetailnet_test

import (
	"bytes"
	"context"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/largetailnet"
	"tailscale.com/types/logger"
)

var (
	flagHookN = flag.Int("rangehook-n", 10_000,
		"size of the initial netmap (peer count) for TestRangeHook")
	flagHookDeltas = flag.Int("rangehook-deltas", 400,
		"number of add+remove delta MapResponses to send while armed")
	flagHookMin = flag.Int("rangehook-min", 0,
		"iteration count at which a range loop is a violation; 0 means rangehook-n / 2")
	flagHookMax = flag.Int("rangehook-max", 500_000,
		"stop recording stacks (but keep counting) after this many violations")
	flagHookOut = flag.String("rangehook-out", "",
		"pprof proto output path; default is rangehook.pprof in the system temp dir")
)

// rangeHookProfile aggregates one sample per violating range loop, keyed
// by call stack. It's a package-level var (not created in the test) so
// -count>1 runs don't panic in pprof.NewProfile on the duplicate name.
var rangeHookProfile = pprof.NewProfile("rangehook")

// TestRangeHook stands up an in-process tsnet client against a synthetic
// N-peer control server, then arms the runtime.DidRange hook while
// streaming a few hundred one-peer add+remove deltas. Any range loop
// anywhere in the process that could iterate (or did iterate) at least
// min times is recorded, with its call stack, into the "rangehook" pprof
// profile.
//
// The whole test binary is instrumented, so control-plane stacks
// (testcontrol, largetailnet) can appear too; they're distinguishable
// by symbol name in the output.
func TestRangeHook(t *testing.T) {
	min := *flagHookMin
	if min == 0 {
		min = *flagHookN / 2
	}

	logf := logger.Discard
	if testing.Verbose() {
		logf = t.Logf
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	t.Cleanup(cancel)

	derpMap := integration.RunDERPAndSTUN(t, logf, "127.0.0.1")

	streamer := largetailnet.New(*flagHookN, derpMap)
	ctrl := &testcontrol.Server{
		DERPMap:      derpMap,
		DNSConfig:    &tailcfg.DNSConfig{},
		AltMapStream: streamer.AltMapStream(),
		Logf:         logf,
	}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	t.Cleanup(ctrl.HTTPTestServer.Close)

	tmp := filepath.Join(t.TempDir(), "tsnet")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: ctrl.HTTPTestServer.URL,
		Hostname:   "rangehook",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logf,
	}
	t.Cleanup(func() { s.Close() })

	upStart := time.Now()
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("tsnet.Server.Up: %v", err)
	}
	t.Logf("initial %d-peer netmap processed in %v", *flagHookN, time.Since(upStart))
	lb := tsnet.TestHooks.LocalBackend(s)

	// Let post-Up asynchronous work (filter build, engine reconfig)
	// from the initial netmap drain before arming, so the profile only
	// reflects steady-state delta processing.
	time.Sleep(2 * time.Second)
	runtime.GC()

	// armed gates the hook: runtime.DidRange fires after every range
	// loop in the whole binary, so the hook must stay cheap (one atomic
	// load) until we're in the delta phase.
	var armed atomic.Bool
	var violations atomic.Int64
	tstest.Replace(t, &runtime.DidRange, func(potentialSize, iterations int) {
		if !armed.Load() {
			return
		}
		if potentialSize < min && iterations < min {
			return
		}
		if violations.Add(1) > int64(*flagHookMax) {
			return
		}
		// Each Add needs a distinct sample key; identical stacks are
		// merged (with counts) when the profile is written. skip=1
		// starts the stack at the runtime.didRange shim's caller,
		// i.e. the function containing the range loop.
		rangeHookProfile.Add(new(byte), 1)
	})

	armed.Store(true)
	deltaStart := time.Now()
	var prevAdded *tailcfg.Node
	for range *flagHookDeltas {
		added := streamer.AllocPeer()
		mr := &tailcfg.MapResponse{
			PeersChanged: []*tailcfg.Node{added},
		}
		if prevAdded != nil {
			mr.PeersRemoved = []tailcfg.NodeID{prevAdded.ID}
		}
		prevAdded = added

		if err := streamer.SendDelta(ctx, mr); err != nil {
			t.Fatalf("SendDelta: %v", err)
		}
		select {
		case <-lb.ForTest().AwaitNodeKey(added.Key):
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for node key %v", added.Key)
		case <-ctx.Done():
			t.Fatalf("ctx done waiting for node key: %v", ctx.Err())
		}
	}
	armed.Store(false)

	t.Logf("%d deltas in %v; %d range violations (loops with potential or actual iterations >= %d)",
		*flagHookDeltas, time.Since(deltaStart), violations.Load(), min)
	if v := violations.Load(); v > int64(*flagHookMax) {
		t.Logf("note: only the first %d violations have recorded stacks", *flagHookMax)
	}

	out := *flagHookOut
	if out == "" {
		out = filepath.Join(os.TempDir(), "rangehook.pprof")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := rangeHookProfile.WriteTo(f, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote pprof proto to %s (view with: go tool pprof -top %s)", out, out)

	logTopStacks(t, rangeHookProfile, 20)
}

// countRx matches the "count @ pc pc ..." header line of each stack in
// a debug=1 count profile dump.
var countRx = regexp.MustCompile(`(?m)^(\d+) @`)

// logTopStacks writes the profile in legacy debug=1 text form, then
// logs the topN unique stacks sorted by descending sample count.
func logTopStacks(t *testing.T, p *pprof.Profile, topN int) {
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		t.Errorf("WriteTo(debug=1): %v", err)
		return
	}
	// Drop the "rangehook profile: total N" header line so the first
	// stack parses as its own block.
	text := buf.String()
	if _, rest, ok := strings.Cut(text, "\n"); ok {
		text = rest
	}
	type entry struct {
		count int
		text  string
	}
	var entries []entry
	for block := range strings.SplitSeq(text, "\n\n") {
		m := countRx.FindStringSubmatch(block)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		entries = append(entries, entry{n, block})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })
	t.Logf("%d unique violating range-loop stacks; top %d:", len(entries), topN)
	for i, e := range entries {
		if i == topN {
			break
		}
		t.Logf("#%d: count=%d\n%s", i+1, e.count, e.text)
	}
}
