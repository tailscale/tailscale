// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vnet"
)

var (
	runPerfTests = flag.Bool("run-perf-tests", false, "run performance measurement tests that are not pass/fail regression tests; wasteful to run in CI")
	perfPCAP     = flag.String("perf-pcap", "", "if non-empty, write a pcap of vnet traffic to this file during TestVnetPerfFreeBSDDownload")
	perfLatency  = flag.Duration("perf-latency", 0, "simulated latency to add to the vnet network in TestVnetPerfFreeBSDDownload")
)

// TestVnetPerfFreeBSDDownload is a benchmark harness for vnet TCP
// throughput, opt-in via --run-perf-tests (in addition to
// --run-vm-tests). It boots a single FreeBSD VM on one vnet network and
// waits only for its TTA agent to connect, which requires the VM to have
// downloaded tailscaled, tailscale, and tta from the vnet's
// files.tailscale VIP. The elapsed time is dominated by that download,
// so the test duration is the benchmark metric.
func TestVnetPerfFreeBSDDownload(t *testing.T) {
	if !*runPerfTests {
		t.Skip("skipping perf test; set --run-perf-tests to run")
	}
	env := New(t)

	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	if *perfPCAP != "" {
		env.cfg.SetPCAPFile(*perfPCAP)
	}
	if *perfLatency > 0 {
		lan.SetLatency(*perfLatency)
	}
	env.AddNode("fbsd", lan, OS(FreeBSD150), DontJoinTailnet())

	t0 := time.Now()
	env.Start()
	t.Logf("Start took %v (boot + binary downloads over vnet)", time.Since(t0).Round(time.Second))

	// Surface fetch(1)'s final progress lines (size, rate, duration per
	// binary) from the serial console log.
	console, err := os.ReadFile(filepath.Join(env.tempDir, "fbsd.log"))
	if err != nil {
		t.Logf("reading console log: %v", err)
		return
	}
	for line := range strings.Lines(string(console)) {
		if strings.Contains(line, "Bps") {
			t.Logf("fetch: %s", strings.TrimSpace(line))
		}
	}
}
