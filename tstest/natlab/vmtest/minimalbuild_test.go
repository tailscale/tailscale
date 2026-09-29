// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestExtraSmall verifies that two gokrazy nodes running tailscale and
// tailscaled built like "build_dist.sh --extra-small" (nearly every optional
// feature omitted) can still send IP packets to each other over WireGuard,
// and, since NAT traversal is kept, find a direct path through easy NATs.
func TestExtraSmall(t *testing.T) {
	testMinimalBuild(t, vmtest.GokrazyExtraSmall, false, vmtest.PingRouteDirect)
}

// TestNoNATTraversal is like [TestExtraSmall] but also without NAT
// traversal. Peers behind separate NATs can't hole punch, so they must
// stay on DERP.
func TestNoNATTraversal(t *testing.T) {
	testMinimalBuild(t, vmtest.GokrazyNoNATTraversal, false, vmtest.PingRouteDERP)
}

// TestNoNATTraversalSameLAN is like [TestNoNATTraversal], but with both
// peers on one LAN, where their advertised local endpoints are directly
// reachable without NAT traversal.
func TestNoNATTraversalSameLAN(t *testing.T) {
	testMinimalBuild(t, vmtest.GokrazyNoNATTraversal, true, vmtest.PingRouteLocal)
}

// TestDERPOnly is like [TestExtraSmall] but also without UDP transport, so
// all traffic must go over DERP.
func TestDERPOnly(t *testing.T) {
	testMinimalBuild(t, vmtest.GokrazyDERPOnly, false, vmtest.PingRouteDERP)
}

// testMinimalBuild starts two nodes running img, either on one LAN or
// behind separate easy NATs, and verifies that IP traffic flows between them
// over WireGuard and that their disco pings settle on wantRoute.
func testMinimalBuild(t *testing.T, img vmtest.OSImage, sameLAN bool, wantRoute vmtest.PingRoute) {
	env := vmtest.New(t)

	aNet := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	bNet := aNet
	if !sameLAN {
		bNet = env.AddNetwork("2.2.2.2", "192.168.2.1/24", vnet.EasyNAT)
	}
	a := env.AddNode("a", aNet, vmtest.OS(img), vmtest.WebServer(8080))
	b := env.AddNode("b", bNet, vmtest.OS(img), vmtest.WebServer(8080))

	env.Start()

	if err := env.Ping(a, b, tailcfg.PingTSMP, 60*time.Second); err != nil {
		t.Fatal(err)
	}

	// Fetch each node's web server from the other over its Tailscale IP.
	// The web server echoes the client's source address, which must be the
	// client's Tailscale IP, proving the TCP connection went through the
	// TUN device and WireGuard.
	aIP := env.Status(a).Self.TailscaleIPs[0]
	bIP := env.Status(b).Self.TailscaleIPs[0]
	for _, tc := range []struct {
		from     *vmtest.Node
		fromIP   string
		to       *vmtest.Node
		toIPPort string
	}{
		{a, aIP.String(), b, bIP.String() + ":8080"},
		{b, bIP.String(), a, aIP.String() + ":8080"},
	} {
		body := env.HTTPGet(tc.from, "http://"+tc.toIPPort+"/")
		want := fmt.Sprintf("Hello world I am %s from %s", tc.to.Name(), tc.fromIP)
		if !strings.Contains(body, want) {
			t.Errorf("HTTP GET from %s to %s: got %q; want %q", tc.from.Name(), tc.toIPPort, body, want)
		}
	}

	if wantRoute != vmtest.PingRouteDERP {
		if _, err := env.PingExpect(a, b, wantRoute, 60*time.Second); err != nil {
			t.Error(err)
		}
		return
	}
	// Seeing a DERP route once proves little, as every connection starts
	// on DERP, so give the nodes time to find a direct path and verify they
	// didn't.
	pr, err := env.PingSettle(a, b, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Endpoint != "" {
		t.Errorf("ping went via endpoint %v; want DERP only", pr.Endpoint)
	}
}
