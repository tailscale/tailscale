// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// scaleResult mirrors the agent's ScaleResult.
type scaleResult struct {
	Peers int
	Steps []struct {
		Peers   int
		AddMS   float64
		MemKB   map[string]int64
		PerPeer map[string]float64
	}
	UpdateEndpointUS, ReplaceIPsUS, AddUS, RemoveUS float64
	RenameUS                                        float64
	DumpMS, TeardownMS                              float64
	TeardownMemKB                                   int64
}

// TestLeanScale measures the tswg module with many peers (TSWG_SCALE_PEERS,
// default 50000) on one VM: memory per peer, the time to add them, and the
// time of single-peer operations at that size, which should not grow with
// it. TSWG_LAB_MEM sets the VMs' memory (MiB) and TSWG_BENCH_CPUS their
// vCPUs (per-CPU allocations grow with them).
func TestLeanScale(t *testing.T) {
	if os.Getenv("TSWG_LEAN_SCALE") == "" {
		t.Skip("set TSWG_LEAN_SCALE=1 (and TSWG_LEAN=1) to run")
	}
	n := 50000
	if s := os.Getenv("TSWG_SCALE_PEERS"); s != "" {
		var err error
		if n, err = strconv.Atoi(s); err != nil {
			t.Fatal(err)
		}
	}
	cpus := 4
	if s := os.Getenv("TSWG_BENCH_CPUS"); s != "" {
		cpus, _ = strconv.Atoi(s)
	}
	lb := newLab(t, cpus)
	lb.setup(modeTSWG, false) // loads the module
	var r scaleResult
	if err := lb.vms[0].do("POST", fmt.Sprintf("/scale?peers=%d&batch=%d", n, max(n/10, 1)), &r); err != nil {
		t.Fatal(err)
	}
	for _, st := range r.Steps {
		t.Logf("%6d peers: batch added in %7.1f ms (%5.1f us/peer); per peer: %5.0f B available, %5.0f B slab, %5.0f B percpu, %5.0f B vmalloc",
			st.Peers, st.AddMS, st.AddMS*1000/float64(r.Steps[0].Peers), st.PerPeer["MemAvailable"], st.PerPeer["Slab"], st.PerPeer["Percpu"], st.PerPeer["VmallocUsed"])
	}
	t.Logf("at %d peers: update endpoint %.0f us, replace allowed IPs %.0f us, add %.0f us, remove %.0f us, rename %.0f us; dump %.0f ms; teardown %.0f ms, giving back %d MB",
		r.Peers, r.UpdateEndpointUS, r.ReplaceIPsUS, r.AddUS, r.RemoveUS, r.RenameUS, r.DumpMS, r.TeardownMS, r.TeardownMemKB/1024)
}
