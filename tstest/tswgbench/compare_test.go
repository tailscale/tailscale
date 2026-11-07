// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
)

// TestLeanCompare compares the TCP throughput of the data planes in
// TSWG_LEAN_COMPARE (comma-separated modes, such as "tswg,wggo") with
// TSWG_COMPARE_RUNS (default 5) runs of TSWG_BENCH_DUR (default 5s) each,
// interleaving the modes so that drift in the host's load affects them
// alike, and reports each mode's median, minimum and maximum.
// TSWG_COMPARE_STREAMS sets the number of TCP streams (default 1).
func TestLeanCompare(t *testing.T) {
	modes := os.Getenv("TSWG_LEAN_COMPARE")
	if modes == "" {
		t.Skip("set TSWG_LEAN_COMPARE=mode,... (and TSWG_LEAN=1) to run")
	}
	envInt := func(k string, def int) int {
		if s := os.Getenv(k); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("%s: %v", k, err)
			}
			return n
		}
		return def
	}
	runs := envInt("TSWG_COMPARE_RUNS", 5)
	streams := envInt("TSWG_COMPARE_STREAMS", 1)
	cpus := envInt("TSWG_BENCH_CPUS", 4)
	dur := 5 * time.Second
	if s := os.Getenv("TSWG_BENCH_DUR"); s != "" {
		var err error
		if dur, err = time.ParseDuration(s); err != nil {
			t.Fatalf("TSWG_BENCH_DUR: %v", err)
		}
	}

	l := newLab(t, cpus)
	results := map[string][]float64{}
	for run := range runs {
		for _, mode := range strings.Split(modes, ",") {
			addr := netip.AddrPortFrom(l.setup(mode, false), benchPort)
			sender, receiver := benchNode{l.vms[0]}, benchNode{l.vms[1]}
			if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
				t.Fatal(err)
			}
			r, err := netbench.RunTCP(sender, receiver, addr, streams, dur)
			if err != nil {
				t.Fatalf("%s run %d: %v", mode, run, err)
			}
			t.Logf("run %d: %s: %.0f Mbps", run, mode, r.Mbps)
			results[mode] = append(results[mode], r.Mbps)
		}
	}
	for _, mode := range strings.Split(modes, ",") {
		rs := slices.Sorted(slices.Values(results[mode]))
		t.Logf("%-8s median %6.0f Mbps (min %6.0f, max %6.0f, %d runs)",
			mode, rs[len(rs)/2], rs[0], rs[len(rs)-1], len(rs))
	}
}
