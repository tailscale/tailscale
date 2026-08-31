// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strings"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestSubnetRouterFreeBSDManyFlows runs the standard subnet-router topology
// against a FreeBSD router with SNAT left at its default (true) and makes
// several sequential HTTP requests, so that each request opens a fresh flow
// through the router's SNAT path.
//
// A single-flow test cannot catch a NAT rule whose translation address is
// wrong on average but right occasionally: PF's "-> (self)" round-robins new
// states across every address on the machine, so one request has decent odds
// of drawing the working (egress interface) address while most flows hang.
// Multiple fresh flows make that failure deterministic. PF state is dumped
// along the way so a failure shows which address each flow was translated to.
func TestSubnetRouterFreeBSDManyFlows(t *testing.T) {
	env := vmtest.New(t)

	clientNet := env.AddNetwork("2.1.1.1", "192.168.1.1/24", "2000:1::1/64", vnet.EasyNAT)
	internalNet := env.AddNetwork("10.0.0.1/24", "2000:2::1/64")

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	sr := env.AddNode("subnet-router", clientNet, internalNet,
		vmtest.OS(vmtest.FreeBSD150),
		vmtest.AdvertiseRoutes("10.0.0.0/24"))
	backend := env.AddNode("backend", internalNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(sr, "10.0.0.0/24")

	dump := func(label string) {
		t.Logf("========== PF STATE: %s ==========", label)
		for _, c := range []struct{ what, cmd string }{
			{"pf info", "pfctl -s info | head -8"},
			{"main nat ruleset", "pfctl -s nat"},
			{"anchor nat (verbose, w/ counters)", "pfctl -a tailscale -vsn"},
			{"state table (port 8080)", "pfctl -s state | grep 8080"},
			{"interfaces", "ifconfig -a | grep -E '^[a-z]|inet '"},
		} {
			out, err := env.SSHExec(sr, c.cmd)
			if err != nil {
				t.Logf("--- %s: error: %v\n%s", c.what, err, out)
				continue
			}
			t.Logf("--- %s:\n%s", c.what, strings.TrimRight(out, "\n"))
		}
	}

	dump("after start, before traffic")

	// Each request opens a fresh flow. A flow whose SNAT translation address
	// is not routable from the backend blackholes at SYN, so count failures
	// too, and record what the backend reported as the source it saw.
	srcSeen := map[string]int{}
	var okCount, failCount int
	targetURL := fmt.Sprintf("http://%s:8080/", backend.LanIP(internalNet))
	for i := range 8 {
		res, err := env.HTTPGetStatus(client, targetURL)
		if err != nil {
			failCount++
			t.Logf("request %d: FAILED: %v", i+1, err)
			continue
		}
		okCount++
		t.Logf("request %d response: %q", i+1, res.Body)
		if _, src, ok := strings.Cut(res.Body, " from "); ok {
			srcSeen[strings.TrimSpace(src)]++
		}
	}

	dump("after traffic")

	t.Logf("results: %d ok, %d failed; source addresses seen by backend:", okCount, failCount)
	for src, n := range srcSeen {
		t.Logf("    %-20s %d requests", src, n)
	}
	if failCount > 0 {
		t.Errorf("%d of 8 requests failed: some flows were translated to an address the backend cannot route back to", failCount)
	}
	if len(srcSeen) > 1 {
		t.Errorf("backend saw %d distinct source addresses %v, want 1: SNAT translation address is unstable across flows", len(srcSeen), srcSeen)
	}
}
