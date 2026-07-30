// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// runUnfixedTests gates tests that reproduce a known-unfixed defect. CI runs
// every Test* in this package, so these must opt in to stay out of it.
var runUnfixedTests = flag.Bool("run-unfixed-tests", false,
	"run tests that reproduce known-unfixed bugs and are expected to fail")

// underlayMTU is the MTU of a Tailscale TUN: what the underlay looks like when
// a tailnet runs over another tailnet.
const underlayMTU = 1280

// bulkTimeout bounds the test side of a bulk transfer. Longer than the 10s cap
// TTA puts on its own fetch, so TTA reports a partial count rather than us
// timing out first.
const bulkTimeout = 20 * time.Second

// TestSmallMTUUnderlayThroughput reproduces the data-plane symptom in #20668:
// on a path narrower than the MTU tailscaled assumes, pings stay healthy while
// bulk transfers collapse, and nothing notices. It asserts both halves.
//
// A full-size TUN packet is 1280 bytes and WireGuard/UDP/IPv4 framing adds 60,
// so it needs 1340 bytes of a 1280-byte underlay and doesn't fit. tailscaled
// sends it anyway: the data path uses tstun.SafeWireMTU() (1360) regardless of
// the real path MTU.
//
// PMTUD doesn't help, which is the useful part. With TS_DEBUG_ENABLE_PMTUD=true
// throughput is byte-identical: only the 1280-byte probe is answered, so
// discovery finds the real MTU, but DefaultTUNMTU discards it per its TODO
// pending PTB generation. Finishing that is #311; see also #9480.
//
// Only the node-to-node underlay is constrained; each node's path to control
// and DERP is netstack-served and unaffected. So a failure here is the data
// plane, not a broken control plane.
func TestSmallMTUUnderlayThroughput(t *testing.T) {
	if !*runUnfixedTests {
		t.Skip("skipping; fails until peer MTU discovery is plumbed into the data path (#311). Set --run-unfixed-tests to run.")
	}
	env := vmtest.New(t)

	// One constrained network per node, so the MTU applies in both directions.
	// EasyNAT so they can still go direct: the point is a direct path that's
	// too narrow, not the absence of one.
	addNode := func(name string, num int) *vmtest.Node {
		nw := env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", num, num, num), // public IP
			fmt.Sprintf("192.168.%d.1/24", num),
			vnet.EasyNAT)
		nw.SetMTU(underlayMTU)
		return env.AddNode(name, nw,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.WebServer(8080))
	}
	a := addNode("a", 1)
	b := addNode("b", 2)

	env.Start()

	// Precondition, not the thing under test: over DERP the underlay MTU
	// wouldn't apply and the test would pass for the wrong reason.
	if err := env.PingExpect(a, b, vmtest.PingRouteDirect, 60*time.Second); err != nil {
		t.Fatalf("precondition: want a direct path between the nodes: %v", err)
	}

	// Small packets fit, so this must keep working even while bulk transfers
	// don't. That asymmetry is the reported symptom.
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		t.Errorf("small-packet TSMP ping failed; expected small packets to fit under the %d-byte MTU: %v",
			underlayMTU, err)
	}

	// 819 full-size packets: can't complete if they're all dropped, but needs
	// only ~100 KiB/s to fit in TTA's 10s budget, which vnet clears easily.
	const wantBytes = 1 << 20
	n, d, err := env.HTTPGetN(a, b, wantBytes, bulkTimeout)
	if err != nil {
		t.Errorf("bulk transfer over a %d-byte-MTU path failed after %d of %d bytes: %v\n"+
			"This is #311 (as seen in #20668): the data path uses tstun.SafeWireMTU() "+
			"(%d bytes) no matter what the real path MTU is, so every full-size packet "+
			"is dropped. Enabling PMTUD does not change this.",
			underlayMTU, n, wantBytes, err, tstun.SafeWireMTU())
		return
	}
	t.Logf("transferred %d bytes in %v (%.1f Mbit/s)",
		n, d.Round(time.Millisecond), float64(n)*8/d.Seconds()/1e6)
}

// TestLargeMTUUnderlayThroughput is the control for
// [TestSmallMTUUnderlayThroughput]: identical but for the underlay MTU, so a
// failure here means the harness is broken rather than the MTU handling. It's
// expected to pass, so it runs in CI.
func TestLargeMTUUnderlayThroughput(t *testing.T) {
	env := vmtest.New(t)

	addNode := func(name string, num int) *vmtest.Node {
		nw := env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", num, num, num),
			fmt.Sprintf("192.168.%d.1/24", num),
			vnet.EasyNAT)
		// Common Ethernet MTU, well above the 1340 a full-size packet needs.
		nw.SetMTU(1500)
		return env.AddNode(name, nw,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.WebServer(8080))
	}
	a := addNode("a", 1)
	b := addNode("b", 2)

	env.Start()

	if err := env.PingExpect(a, b, vmtest.PingRouteDirect, 60*time.Second); err != nil {
		t.Fatalf("precondition: want a direct path between the nodes: %v", err)
	}

	const wantBytes = 1 << 20
	n, d, err := env.HTTPGetN(a, b, wantBytes, bulkTimeout)
	if err != nil {
		t.Fatalf("bulk transfer over a 1500-byte-MTU path failed; "+
			"the harness itself may be broken: %v", err)
	}
	t.Logf("transferred %d bytes in %v (%.1f Mbit/s)",
		n, d.Round(time.Millisecond), float64(n)*8/d.Seconds()/1e6)
}
