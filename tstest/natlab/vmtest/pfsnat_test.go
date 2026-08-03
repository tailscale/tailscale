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
// through the router's PF NAT rule.
//
// A single-flow test cannot catch a NAT rule whose translation address pool
// is wrong on average but right occasionally: "-> (self)" round-robins new
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
			{"pf info", "pfctl -s info"},
			{"main nat ruleset", "pfctl -s nat"},
			{"anchor nat (verbose, w/ counters)", "pfctl -a tailscale -vsn"},
			{"anchor filter (verbose)", "pfctl -a tailscale -vsr"},
			{"state table", "pfctl -s state | head -20"},
			{"interfaces", "ifconfig -a | grep -E '^[a-z]|inet '"},
			{"routes", "netstat -rn -f inet"},
			{"forwarding", "sysctl net.inet.ip.forwarding"},
		} {
			out, err := env.Exec(sr, c.cmd)
			if err != nil {
				t.Logf("--- %s: ERROR %v\n%s", c.what, err, out)
				continue
			}
			t.Logf("--- %s:\n%s", c.what, strings.TrimRight(out, "\n"))
		}
	}

	dump("after start, before traffic")

	// Repeat the request several times. "-> (self)" expands to every address
	// on the box (here: the WAN IP, the LAN IP, the QEMU user-net IP and
	// 127.0.0.1) and pf's round-robin pool cycles through that list per new
	// state, so a single successful flow does not prove the translation
	// address is chosen correctly. A flow translated to a non-LAN address
	// blackholes (the backend cannot route the reply), so count failures too,
	// and after each request record what the state table says the flow was
	// translated to.
	srcSeen := map[string]int{}
	var okCount, failCount int
	srLanIP := sr.LanIP(internalNet).String()
	for i := range 8 {
		body, err := env.HTTPGetErr(client, fmt.Sprintf("http://%s:8080/", backend.LanIP(internalNet)))
		if err != nil {
			failCount++
			t.Logf("request %d: FAILED: %v", i+1, err)
		} else {
			okCount++
			t.Logf("request %d response: %q", i+1, body)
			if _, src, ok := strings.Cut(body, " from "); ok {
				srcSeen[strings.TrimSpace(src)]++
			}
		}
		if out, err := env.Exec(sr, "pfctl -s state | grep 8080"); err == nil {
			t.Logf("request %d states:\n%s", i+1, strings.TrimRight(out, "\n"))
		}
	}

	dump("after traffic")

	t.Logf("results: %d ok, %d failed; source addresses seen by backend (subnet router LAN IP is %s):", okCount, failCount, srLanIP)
	for src, n := range srcSeen {
		t.Logf("    %-20s %d requests", src, n)
	}
	if failCount > 0 {
		t.Errorf("%d of 8 requests failed: \"-> (self)\" round-robin translated some flows to a non-LAN address", failCount)
	}
	for src := range srcSeen {
		if src != srLanIP {
			t.Errorf("backend saw source %q, want the subnet router's LAN IP %q", src, srLanIP)
		}
	}
}
