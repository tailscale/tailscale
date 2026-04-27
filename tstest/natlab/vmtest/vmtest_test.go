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

// TestInterNetworkTCP verifies that vnet routes raw TCP between simulated
// networks: a non-Tailscale VM on one NAT'd LAN can reach a webserver on a
// different network using a 1:1 NAT, and the webserver sees the client's
// network's WAN IP as the source (post-NAT).
func TestInterNetworkTCP(t *testing.T) {
	env := vmtest.New(t)

	const (
		clientWAN = "1.0.0.1"
		webWAN    = "5.0.0.1"
	)

	clientNet := env.AddNetwork(clientWAN, "192.168.1.1/24", vnet.EasyNAT)
	webNet := env.AddNetwork(webWAN, "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet())
	env.AddNode("webserver", webNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()

	body := env.HTTPGet(client, fmt.Sprintf("http://%s:8080/", webWAN))
	t.Logf("response: %s", body)
	if !strings.Contains(body, "Hello world I am webserver") {
		t.Fatalf("unexpected response: %q", body)
	}
	if !strings.Contains(body, "from "+clientWAN) {
		t.Fatalf("expected source %q in response, got %q", clientWAN, body)
	}
}

// TestSubnetRouterPublicIP verifies that toggling --accept-routes on the
// client switches between dialing a webserver directly and routing through a
// subnet router that advertises the webserver's public IP range.
//
// Topology: client, subnet router, and webserver each live behind their own
// NAT'd network with distinct WAN IPs; the subnet router advertises the
// webserver's network as a route. The webserver echoes the source IP it
// sees:
//   - accept-routes=off: client dials webserver directly; source is client's WAN.
//   - accept-routes=on:  client tunnels to the subnet router, which forwards
//     and SNATs; source is subnet router's WAN.
func TestSubnetRouterPublicIP(t *testing.T) {
	env := vmtest.New(t)

	const (
		clientWAN = "1.0.0.1"
		routerWAN = "2.0.0.1"
		webWAN    = "5.0.0.1"
		webRoute  = "5.0.0.0/24"
	)

	clientNet := env.AddNetwork(clientWAN, "192.168.1.1/24", vnet.EasyNAT)
	routerNet := env.AddNetwork(routerWAN, "192.168.2.1/24", vnet.EasyNAT)
	webNet := env.AddNetwork(webWAN, "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	sr := env.AddNode("subnet-router", routerNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes(webRoute))
	env.AddNode("webserver", webNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	// ApproveRoutes also turns on RouteAll on the client.
	env.ApproveRoutes(sr, webRoute)

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	check := func(label, wantSrc string) {
		t.Helper()
		body := env.HTTPGet(client, webURL)
		t.Logf("[%s] response: %s", label, body)
		if !strings.Contains(body, "Hello world I am webserver") {
			t.Fatalf("[%s] unexpected webserver response: %q", label, body)
		}
		if !strings.Contains(body, "from "+wantSrc) {
			t.Fatalf("[%s] expected source %q in response, got %q", label, wantSrc, body)
		}
	}

	// accept-routes=on (set by ApproveRoutes): traffic flows via the subnet router.
	check("accept-routes=on", routerWAN)

	// accept-routes=off: client dials the webserver directly.
	env.SetAcceptRoutes(client, false)
	check("accept-routes=off", clientWAN)

	// Toggle back on to confirm the transition works in both directions.
	env.SetAcceptRoutes(client, true)
	check("accept-routes=on (again)", routerWAN)
}

// TestSubnetRouterAndExitNode checks how the subnet router and exit node
// preferences interact. Topology: client, subnet router, exit node, and
// webserver, each on its own NAT'd network with distinct WAN IPs. The subnet
// router advertises the webserver's network (5.0.0.0/24); the exit node
// advertises 0.0.0.0/0 + ::/0. The webserver echoes the source IP it sees:
//
//	exit=off, subnet=off → client's WAN  (direct dial)
//	exit=off, subnet=on  → subnet router's WAN
//	exit=on,  subnet=off → exit node's WAN
//	exit=on,  subnet=on  → subnet router's WAN  (more-specific /24 beats /0)
func TestSubnetRouterAndExitNode(t *testing.T) {
	env := vmtest.New(t)

	const (
		clientWAN = "1.0.0.1"
		routerWAN = "2.0.0.1"
		exitWAN   = "3.0.0.1"
		webWAN    = "5.0.0.1"
		webRoute  = "5.0.0.0/24"
	)

	clientNet := env.AddNetwork(clientWAN, "192.168.1.1/24", vnet.EasyNAT)
	routerNet := env.AddNetwork(routerWAN, "192.168.2.1/24", vnet.EasyNAT)
	exitNet := env.AddNetwork(exitWAN, "192.168.3.1/24", vnet.EasyNAT)
	webNet := env.AddNetwork(webWAN, "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	sr := env.AddNode("subnet-router", routerNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes(webRoute))
	exit := env.AddNode("exit", exitNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes("0.0.0.0/0,::/0"))
	env.AddNode("webserver", webNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(sr, webRoute)
	env.ApproveRoutes(exit, "0.0.0.0/0", "::/0")
	// Don't let the exit node itself forward via the subnet router: when the
	// client is using the exit node only, we want the exit node to egress to
	// the simulated internet directly so the webserver sees the exit's WAN.
	env.SetAcceptRoutes(exit, false)

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	tests := []struct {
		name    string // subtest name; describes (exit, subnet) toggles
		exit    *vmtest.Node
		subnet  bool
		wantSrc string
	}{
		{"exit-off,subnet-off", nil, false, clientWAN},
		{"exit-off,subnet-on", nil, true, routerWAN},
		{"exit-on,subnet-off", exit, false, exitWAN},
		// More-specific 5.0.0.0/24 from sr beats 0.0.0.0/0 from exit.
		{"exit-on,subnet-on", exit, true, routerWAN},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env.SetExitNode(client, tc.exit)
			env.SetAcceptRoutes(client, tc.subnet)
			body := env.HTTPGet(client, webURL)
			t.Logf("response: %s", body)
			if !strings.Contains(body, "Hello world I am webserver") {
				t.Fatalf("unexpected webserver response: %q", body)
			}
			if !strings.Contains(body, "from "+tc.wantSrc) {
				t.Fatalf("expected source %q in response, got %q", tc.wantSrc, body)
			}
		})
	}
}

// TestExitNode verifies that switching the client's exit node setting between
// off, exit1, and exit2 correctly routes the client's internet traffic.
//
// Topology: each of the client and the two exit nodes lives behind its own NAT
// with a unique WAN IP, and a webserver lives on yet another network using a
// 1:1 NAT so it's reachable from the simulated internet at a stable address.
// The webserver echoes the source IP of incoming requests, so we can tell
// which network's NAT the client's traffic egressed through:
//   - off:  source is the client's network WAN IP.
//   - exit1: source is exit1's network WAN IP.
//   - exit2: source is exit2's network WAN IP.
func TestExitNode(t *testing.T) {
	env := vmtest.New(t)

	const (
		clientWAN = "1.0.0.1"
		exit1WAN  = "2.0.0.1"
		exit2WAN  = "3.0.0.1"
		webWAN    = "5.0.0.1"
	)

	clientNet := env.AddNetwork(clientWAN, "192.168.1.1/24", vnet.EasyNAT)
	exit1Net := env.AddNetwork(exit1WAN, "192.168.2.1/24", vnet.EasyNAT)
	exit2Net := env.AddNetwork(exit2WAN, "192.168.3.1/24", vnet.EasyNAT)
	webNet := env.AddNetwork(webWAN, "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	exit1 := env.AddNode("exit1", exit1Net,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes("0.0.0.0/0,::/0"))
	exit2 := env.AddNode("exit2", exit2Net,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes("0.0.0.0/0,::/0"))
	env.AddNode("webserver", webNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(exit1, "0.0.0.0/0", "::/0")
	env.ApproveRoutes(exit2, "0.0.0.0/0", "::/0")

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	tests := []struct {
		name    string // subtest name
		exit    *vmtest.Node
		wantSrc string
	}{
		{"off", nil, clientWAN},
		{"exit1", exit1, exit1WAN},
		{"exit2", exit2, exit2WAN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env.SetExitNode(client, tt.exit)
			body := env.HTTPGet(client, webURL)
			t.Logf("response: %s", body)
			if !strings.Contains(body, "Hello world I am webserver") {
				t.Fatalf("unexpected webserver response: %q", body)
			}
			if !strings.Contains(body, "from "+tt.wantSrc) {
				t.Fatalf("expected source %q in response, got %q", tt.wantSrc, body)
			}
		})
	}
}
