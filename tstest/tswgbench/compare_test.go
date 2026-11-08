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
// TSWG_COMPARE_STREAMS sets the number of TCP streams (default 1). With
// TSWG_COMPARE_LOAD=rtt, it compares UDP round trip times instead, idle
// and under a 1-stream TCP load; with TSWG_COMPARE_LOAD=fetch, fetches (as
// netbench.RunTCPFetch) of 1 MiB from VM 0 by VM 1.
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

	rtt := os.Getenv("TSWG_COMPARE_LOAD") == "rtt"
	fetch := os.Getenv("TSWG_COMPARE_LOAD") == "fetch"

	l := newLab(t, cpus)
	// results maps a mode and metric ("Mbps", "idle p50 ms", ...) to the
	// runs' values.
	type key struct{ mode, metric string }
	results := map[key][]float64{}
	var metrics []string
	record := func(mode, metric string, v float64) {
		if !slices.Contains(metrics, metric) {
			metrics = append(metrics, metric)
		}
		results[key{mode, metric}] = append(results[key{mode, metric}], v)
	}
	for run := range runs {
		for _, mode := range strings.Split(modes, ",") {
			addr := netip.AddrPortFrom(l.setup(mode, false), benchPort)
			sender, receiver := benchNode{l.vms[0]}, benchNode{l.vms[1]}
			if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
				t.Fatal(err)
			}
			if fetch {
				// VM 1 fetches from VM 0, so VM 0 sends the data, as
				// in the other loads.
				back := netip.AddrPortFrom(tunnel4(0), benchPort)
				if mode == modePlain {
					back = netip.AddrPortFrom(l.vms[0].under4, benchPort)
				}
				if err := sender.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
					t.Fatal(err)
				}
				r, err := netbench.RunTCPFetch([]netbench.Node{receiver}, sender, nil, back, streams, 1<<20, 500, dur)
				if err != nil {
					t.Fatalf("%s run %d: %v", mode, run, err)
				}
				t.Logf("run %d: %s: %.0f Mbps, %d responses, sender %.2f CPU-s/GB",
					run, mode, r.Mbps, r.Responses, r.ReceiverCPUSecPerGB)
				record(mode, "Mbps", r.Mbps)
				record(mode, "send CPU-s/GB", r.ReceiverCPUSecPerGB)
				continue
			}
			if !rtt {
				r, err := netbench.RunTCP(sender, receiver, addr, streams, dur)
				if err != nil {
					t.Fatalf("%s run %d: %v", mode, run, err)
				}
				t.Logf("run %d: %s: %.0f Mbps, sender %.2f, receiver %.2f CPU-s/GB",
					run, mode, r.Mbps, r.SenderCPUSecPerGB, r.ReceiverCPUSecPerGB)
				record(mode, "Mbps", r.Mbps)
				record(mode, "send CPU-s/GB", r.SenderCPUSecPerGB)
				record(mode, "recv CPU-s/GB", r.ReceiverCPUSecPerGB)
				continue
			}
			idle, err := netbench.RunRTT(sender, addr, 400)
			if err != nil {
				t.Fatalf("%s run %d: %v", mode, run, err)
			}
			var loaded netbench.RTT
			var tcp netbench.TCPResult
			var loadErr error
			done := make(chan bool)
			go func() {
				tcp, loadErr = netbench.RunTCP(sender, receiver, addr, 1, 4*time.Second)
				close(done)
			}()
			time.Sleep(500 * time.Millisecond) // let the load ramp up
			loaded, err = netbench.RunRTT(sender, addr, 400)
			<-done
			if err != nil || loadErr != nil {
				t.Fatalf("%s run %d: %v, %v", mode, run, err, loadErr)
			}
			t.Logf("run %d: %s: idle p50 %.2f p99 %.2f ms; loaded p50 %.2f p99 %.2f ms (%.0f Mbps)",
				run, mode, idle.P50, idle.P99, loaded.P50, loaded.P99, tcp.Mbps)
			record(mode, "idle p50 ms", idle.P50)
			record(mode, "idle p99 ms", idle.P99)
			record(mode, "loaded p50 ms", loaded.P50)
			record(mode, "loaded p99 ms", loaded.P99)
			record(mode, "loaded Mbps", tcp.Mbps)
		}
	}
	for _, metric := range metrics {
		for _, mode := range strings.Split(modes, ",") {
			rs := slices.Sorted(slices.Values(results[key{mode, metric}]))
			t.Logf("%-8s %-14s median %8.2f (min %8.2f, max %8.2f, %d runs)",
				mode, metric, rs[len(rs)/2], rs[0], rs[len(rs)-1], len(rs))
		}
	}
}
