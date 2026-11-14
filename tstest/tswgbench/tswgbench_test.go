// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
	"tailscale.com/wgengine/tswg"
)

// TestLeanSmoke checks that every data plane carries traffic between the
// lab's VMs, over both an IPv4 and an IPv6 underlay, including that tswg
// and the kernel's WireGuard handshake with their peer at the right
// address family.
func TestLeanSmoke(t *testing.T) {
	lb := newLab(t, 2)
	for _, v6 := range []bool{false, true} {
		fam := "v4"
		if v6 {
			fam = "v6"
		}
		for _, mode := range allModes {
			t.Run(fam+"/"+mode, func(t *testing.T) {
				addr := netip.AddrPortFrom(lb.setup(mode, v6), benchPort)
				sender, receiver := benchNode{lb.vms[0]}, benchNode{lb.vms[1]}
				if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
					t.Fatal(err)
				}
				rtt, err := netbench.RunRTT(sender, addr, 20)
				if err != nil {
					t.Fatal(err)
				}
				if rtt.Samples == 0 {
					t.Fatalf("no RTT replies: %+v", rtt)
				}
				tcp, err := netbench.RunTCP(sender, receiver, addr, 1, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if tcp.Mbps <= 0 {
					t.Fatalf("no TCP throughput: %+v", tcp)
				}
				t.Logf("rtt p50 %.2fms, tcp %.0f Mbps", rtt.P50, tcp.Mbps)

				if mode == modeTSWG || mode == modeKernelWG {
					var d tswg.Device
					if err := lb.vms[0].do("GET", "/show", &d); err != nil {
						t.Fatal(err)
					}
					if len(d.Peers) != 1 {
						t.Fatalf("%d peers", len(d.Peers))
					}
					p := d.Peers[0]
					if p.LastHandshake.IsZero() {
						t.Errorf("no handshake: %+v", p)
					}
					if p.Endpoint.Addr().Is6() != v6 {
						t.Errorf("peer endpoint %v; want IPv6=%v", p.Endpoint, v6)
					}
				}
			})
		}
	}
}

// TestLeanBenchmark compares the data planes (wireguard-go, tswg, the
// kernel's WireGuard, and no tunnel) between the lab's VMs; see
// netbench.RunSuite for what it measures.
//
// It only runs with TSWG_LEAN=1 and TSWG_LEAN_BENCH=1. TSWG_BENCH_CPUS
// sets each VM's virtual CPUs (default 4), TSWG_BENCH_DUR the length of
// each throughput run (default 10s), TSWG_BENCH_V6=1 adds runs over the
// IPv6 underlay, and TSWG_BENCH_OUT names a file for the results as JSON.
func TestLeanBenchmark(t *testing.T) {
	if os.Getenv("TSWG_LEAN_BENCH") == "" {
		t.Skip("set TSWG_LEAN_BENCH=1 (and TSWG_LEAN=1) to run")
	}
	cpus := 4
	if s := os.Getenv("TSWG_BENCH_CPUS"); s != "" {
		var err error
		if cpus, err = strconv.Atoi(s); err != nil {
			t.Fatalf("TSWG_BENCH_CPUS: %v", err)
		}
	}
	dur := 10 * time.Second
	if s := os.Getenv("TSWG_BENCH_DUR"); s != "" {
		var err error
		if dur, err = time.ParseDuration(s); err != nil {
			t.Fatalf("TSWG_BENCH_DUR: %v", err)
		}
	}
	families := []bool{false}
	if os.Getenv("TSWG_BENCH_V6") != "" {
		families = append(families, true)
	}

	lb := newLab(t, cpus)
	// wireguard-go first, so the table's ratios are relative to it.
	modes := []string{modeWGGo, modeTSWG, modeKernelWG, modePlain}
	all := map[string]map[string]*netbench.SuiteResult{}
	for _, v6 := range families {
		fam := "v4"
		if v6 {
			fam = "v6"
		}
		var results []*netbench.SuiteResult
		all[fam] = map[string]*netbench.SuiteResult{}
		for _, mode := range modes {
			t.Logf("benchmarking %s over %s...", mode, fam)
			addr := netip.AddrPortFrom(lb.setup(mode, v6), benchPort)
			r, err := netbench.RunSuite(benchNode{lb.vms[0]}, benchNode{lb.vms[1]}, addr, dur)
			if err != nil {
				t.Fatalf("%s over %s: %v", mode, fam, err)
			}
			results = append(results, r)
			all[fam][mode] = r
		}
		t.Logf("results over the %s underlay (%d vCPUs per VM, %v runs):\n%s",
			fam, cpus, dur, netbench.FormatTable(modes, results))
	}
	if out := os.Getenv("TSWG_BENCH_OUT"); out != "" {
		j, err := json.MarshalIndent(map[string]any{
			"harness": "lean",
			"cpus":    cpus,
			"dur":     dur.String(),
			"results": all,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, j, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
