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

func TestSubnetRouter(t *testing.T) {
	testSubnetRouterForOS(t, vmtest.Ubuntu2404)
}

func TestSubnetRouterFreeBSD(t *testing.T) {
	testSubnetRouterForOS(t, vmtest.FreeBSD150)
}

func testSubnetRouterForOS(t testing.TB, srOS vmtest.OSImage) {
	t.Helper()
	env := vmtest.New(t)

	clientNet := env.AddNetwork("2.1.1.1", "192.168.1.1/24", "2000:1::1/64", vnet.EasyNAT)
	internalNet := env.AddNetwork("10.0.0.1/24", "2000:2::1/64")

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	sr := env.AddNode("subnet-router", clientNet, internalNet,
		vmtest.OS(srOS),
		vmtest.AdvertiseRoutes("10.0.0.0/24"))
	backend := env.AddNode("backend", internalNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(sr, "10.0.0.0/24")

	body := env.HTTPGet(client, fmt.Sprintf("http://%s:8080/", backend.LanIP(internalNet)))
	if !strings.Contains(body, "Hello world I am backend") {
		t.Fatalf("got %q", body)
	}
}

func TestSiteToSite(t *testing.T) {
	testSiteToSite(t, vmtest.Ubuntu2404)
}

// testSiteToSite runs a site-to-site subnet routing test with
// --snat-subnet-routes=false, verifying that original source IPs are preserved
// across Tailscale subnet routes.
//
// Topology:
//
//	Site A:  backend-a (10.1.0.0/24) ← → sr-a (WAN + LAN-A)
//	Site B:  backend-b (10.2.0.0/24) ← → sr-b (WAN + LAN-B)
//
// Both subnet routers are on Tailscale with --snat-subnet-routes=false.
// The test sends HTTP from backend-a to backend-b through the subnet routers
// and verifies that backend-b sees backend-a's LAN IP (not the subnet router's).
func testSiteToSite(t *testing.T, srOS vmtest.OSImage) {
	env := vmtest.New(t)

	// WAN networks for each site (each behind NAT).
	wanA := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	wanB := env.AddNetwork("3.1.1.1", "192.168.2.1/24", vnet.EasyNAT)

	// Internal LAN for each site.
	lanA := env.AddNetwork("10.1.0.1/24")
	lanB := env.AddNetwork("10.2.0.1/24")

	// Subnet routers: each on its WAN + LAN, advertising the local LAN,
	// with SNAT disabled to preserve source IPs.
	srA := env.AddNode("sr-a", wanA, lanA,
		vmtest.OS(srOS),
		vmtest.AdvertiseRoutes("10.1.0.0/24"),
		vmtest.SNATSubnetRoutes(false))
	srB := env.AddNode("sr-b", wanB, lanB,
		vmtest.OS(srOS),
		vmtest.AdvertiseRoutes("10.2.0.0/24"),
		vmtest.SNATSubnetRoutes(false))

	// Backend servers on each site's LAN (not on Tailscale).
	// Use Ubuntu so we can SSH in to add static routes.
	backendA := env.AddNode("backend-a", lanA,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))
	backendB := env.AddNode("backend-b", lanB,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(srA, "10.1.0.0/24")
	env.ApproveRoutes(srB, "10.2.0.0/24")

	// Add static routes on the backends so that traffic to the remote site's
	// subnet goes through the local subnet router. This mirrors how a real
	// site-to-site deployment is configured.
	srALanIP := srA.LanIP(lanA).String()
	srBLanIP := srB.LanIP(lanB).String()
	t.Logf("sr-a LAN IP: %s, sr-b LAN IP: %s", srALanIP, srBLanIP)
	t.Logf("backend-a LAN IP: %s, backend-b LAN IP: %s", backendA.LanIP(lanA), backendB.LanIP(lanB))

	env.AddRoute(backendA, "10.2.0.0/24", srALanIP)
	env.AddRoute(backendB, "10.1.0.0/24", srBLanIP)

	// Make an HTTP request from backend-a to backend-b through the subnet routers.
	// TTA's /http-get falls back to direct dial on non-Tailscale nodes.
	backendBIP := backendB.LanIP(lanB)
	body := env.HTTPGet(backendA, fmt.Sprintf("http://%s:8080/", backendBIP))
	t.Logf("response: %s", body)

	if !strings.Contains(body, "Hello world I am backend-b") {
		t.Fatalf("expected response from backend-b, got %q", body)
	}

	// Verify the source IP was preserved. With --snat-subnet-routes=false,
	// backend-b should see backend-a's LAN IP as the source, not sr-b's LAN IP.
	backendAIP := backendA.LanIP(lanA).String()
	if !strings.Contains(body, "from "+backendAIP) {
		t.Fatalf("source IP not preserved: expected %q in response, got %q", backendAIP, body)
	}
}
