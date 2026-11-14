// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/tstest/tswgbench/netbench"
)

// ttaBenchNode is a netbench.Node for a natlab VM, via tta's /tswg/bench/
// endpoints.
type ttaBenchNode struct{ n *vmtest.Node }

func (b ttaBenchNode) Do(method, path string, v any) error {
	res, err := ttaErrTimeout(b.n, method, "/tswg/bench/"+path, nil, 5*time.Minute)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal([]byte(res), v)
}

// runBench runs the benchmark suite from f's first node to its second,
// over their direct path, which is on their shared LAN.
func (f *tswgTailscaled) runBench(kernelMode bool, dur time.Duration) *netbench.SuiteResult {
	f.t.Helper()
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	if _, err := f.env.PingExpect(n1, n2, vmtest.PingRouteLocal, 60*time.Second); err != nil {
		f.t.Fatalf("no direct LAN path: %v", err)
	}
	if kernelMode {
		f.waitKernelPath(n1, ip2, true, 60*time.Second)
	}
	// And the tunnel actually carries traffic (waitKernelPath only looks
	// at the kernel's endpoint).
	f.env.LANPing(n1, ip2)
	r, err := netbench.RunSuite(ttaBenchNode{n1}, ttaBenchNode{n2}, netip.AddrPortFrom(ip2, 5201), dur)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// TestTSWGBenchmark compares tailscaled with the tswg kernel data plane
// against tailscaled in its usual TUN mode (wireguard-go) on the same pair
// of gokrazy VMs on one natlab LAN; see netbench.RunSuite for what it
// measures.
//
// It's slow, so it only runs with TSWG_BENCH=1. TSWG_BENCH_CPUS sets each
// VM's virtual CPUs (default 2), TSWG_BENCH_DUR the length of each
// throughput run (default 10s), and TSWG_BENCH_OUT a file to write the
// results to as JSON.
//
// natlab's network is simulated in userspace on the host, which caps the
// absolute numbers; the CPU cost per byte and per packet inside the VMs,
// and the comparison between data planes, are what this measures. For
// bare data plane numbers, see tailscale.com/tstest/tswgbench.
func TestTSWGBenchmark(t *testing.T) {
	if os.Getenv("TSWG_BENCH") == "" {
		t.Skip("set TSWG_BENCH=1 to run")
	}
	cpus := 2
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

	ko := buildTSWGForGokrazy(t, tswgDir(t))
	f := &tswgTailscaled{t: t, env: vmtest.New(t)}
	lan := f.env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	for i := range 2 {
		f.nodes = append(f.nodes, f.env.AddNode(fmt.Sprintf("tswg%d", i+1), lan,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.CPUs(cpus),
			vnet.TailscaledEnv{Key: "TS_DEBUG_TSWG", Value: "1"}))
	}
	f.env.Start()

	// tailscaled starts in TUN mode (wireguard-go), since the module isn't
	// loaded yet.
	for _, n := range f.nodes {
		if _, err := f.show(n); err == nil {
			t.Fatalf("[%s] has a tswg device before the module was loaded", n.Name())
		}
	}
	t.Logf("benchmarking wireguard-go...")
	wg := f.runBench(false, dur)

	for _, n := range f.nodes {
		tta(t, n, "POST", "/tswg/load", ko)
		f.env.RestartTailscaled(n)
	}
	for _, n := range f.nodes {
		f.waitKernelReady(n)
	}
	t.Logf("benchmarking tswg...")
	k := f.runBench(true, dur)

	t.Logf("results (%d vCPUs per VM, %v runs):\n%s", cpus, dur,
		netbench.FormatTable([]string{"wireguard-go", "tswg"}, []*netbench.SuiteResult{wg, k}))
	if out := os.Getenv("TSWG_BENCH_OUT"); out != "" {
		j, err := json.MarshalIndent(map[string]any{
			"harness": "natlab",
			"cpus":    cpus,
			"dur":     dur.String(),
			"results": map[string]*netbench.SuiteResult{"wireguard-go": wg, "tswg": k},
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, j, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
