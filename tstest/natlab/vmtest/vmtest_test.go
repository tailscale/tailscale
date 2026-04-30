// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

func TestMacOSAndLinuxCanPing(t *testing.T) {
	env := vmtest.New(t)

	lan := env.AddNetwork("192.168.1.1/24")

	linux := env.AddNode("linux", lan,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet())
	macos := env.AddNode("macos", lan,
		vmtest.OS(vmtest.MacOS),
		vmtest.DontJoinTailnet())

	env.Start()

	env.LANPing(linux, macos.LanIP(lan))
}

func TestTwoMacOSVMsCanPing(t *testing.T) {
	env := vmtest.New(t)

	lan := env.AddNetwork("192.168.1.1/24")

	mac1 := env.AddNode("mac1", lan,
		vmtest.OS(vmtest.MacOS),
		vmtest.DontJoinTailnet())
	mac2 := env.AddNode("mac2", lan,
		vmtest.OS(vmtest.MacOS),
		vmtest.DontJoinTailnet())

	env.Start()

	// Both macOS VMs have TTA. Ping from mac1 to mac2 and vice versa.
	env.LANPing(mac1, mac2.LanIP(lan))
	env.LANPing(mac2, mac1.LanIP(lan))
}

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

	// Declare test-specific steps for the web UI.
	approveStep := env.AddStep("Approve subnet routes")
	httpStep := env.AddStep("HTTP GET through subnet router")

	env.Start()

	approveStep.Begin()
	env.ApproveRoutes(sr, "10.0.0.0/24")
	approveStep.End(nil)

	httpStep.Begin()
	body := env.HTTPGet(client, fmt.Sprintf("http://%s:8080/", backend.LanIP(internalNet)))
	if !strings.Contains(body, "Hello world I am backend") {
		httpStep.End(fmt.Errorf("got %q", body))
		t.Fatalf("got %q", body)
	}
	httpStep.End(nil)
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

	// Declare test-specific steps for the web UI.
	approveStep := env.AddStep("Approve subnet routes (sr-a, sr-b)")
	staticRouteStep := env.AddStep("Add static routes on backends")
	httpStep := env.AddStep("HTTP GET through site-to-site")

	env.Start()

	approveStep.Begin()
	env.ApproveRoutes(srA, "10.1.0.0/24")
	env.ApproveRoutes(srB, "10.2.0.0/24")
	approveStep.End(nil)

	// Add static routes on the backends so that traffic to the remote site's
	// subnet goes through the local subnet router. This mirrors how a real
	// site-to-site deployment is configured.
	srALanIP := srA.LanIP(lanA).String()
	srBLanIP := srB.LanIP(lanB).String()
	t.Logf("sr-a LAN IP: %s, sr-b LAN IP: %s", srALanIP, srBLanIP)
	t.Logf("backend-a LAN IP: %s, backend-b LAN IP: %s", backendA.LanIP(lanA), backendB.LanIP(lanB))

	staticRouteStep.Begin()
	env.AddRoute(backendA, "10.2.0.0/24", srALanIP)
	env.AddRoute(backendB, "10.1.0.0/24", srBLanIP)
	staticRouteStep.End(nil)

	// Make an HTTP request from backend-a to backend-b through the subnet routers.
	// TTA's /http-get falls back to direct dial on non-Tailscale nodes.
	httpStep.Begin()
	backendBIP := backendB.LanIP(lanB)
	body := env.HTTPGet(backendA, fmt.Sprintf("http://%s:8080/", backendBIP))
	t.Logf("response: %s", body)

	if !strings.Contains(body, "Hello world I am backend-b") {
		httpStep.End(fmt.Errorf("expected response from backend-b, got %q", body))
		t.Fatalf("expected response from backend-b, got %q", body)
	}

	// Verify the source IP was preserved. With --snat-subnet-routes=false,
	// backend-b should see backend-a's LAN IP as the source, not sr-b's LAN IP.
	backendAIP := backendA.LanIP(lanA).String()
	if !strings.Contains(body, "from "+backendAIP) {
		httpStep.End(fmt.Errorf("source IP not preserved: expected %q in response, got %q", backendAIP, body))
		t.Fatalf("source IP not preserved: expected %q in response, got %q", backendAIP, body)
	}
	httpStep.End(nil)
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

	// Declare test-specific steps for the web UI.
	httpStep := env.AddStep("HTTP GET across networks via NAT")

	env.Start()

	httpStep.Begin()
	body := env.HTTPGet(client, fmt.Sprintf("http://%s:8080/", webWAN))
	t.Logf("response: %s", body)
	if !strings.Contains(body, "Hello world I am webserver") {
		httpStep.End(fmt.Errorf("unexpected response: %q", body))
		t.Fatalf("unexpected response: %q", body)
	}
	if !strings.Contains(body, "from "+clientWAN) {
		httpStep.End(fmt.Errorf("expected source %q in response, got %q", clientWAN, body))
		t.Fatalf("expected source %q in response, got %q", clientWAN, body)
	}
	httpStep.End(nil)
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

	// Declare test-specific steps for the web UI.
	approveStep := env.AddStep("Approve subnet route (public IP)")
	checkOn1Step := env.AddStep("HTTP GET (accept-routes=on)")
	checkOffStep := env.AddStep("HTTP GET (accept-routes=off)")
	checkOn2Step := env.AddStep("HTTP GET (accept-routes=on, again)")

	env.Start()
	// ApproveRoutes also turns on RouteAll on the client.
	approveStep.Begin()
	env.ApproveRoutes(sr, webRoute)
	approveStep.End(nil)

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	check := func(step *vmtest.Step, label, wantSrc string) {
		t.Helper()
		step.Begin()
		body := env.HTTPGet(client, webURL)
		t.Logf("[%s] response: %s", label, body)
		if !strings.Contains(body, "Hello world I am webserver") {
			step.End(fmt.Errorf("[%s] unexpected webserver response: %q", label, body))
			t.Fatalf("[%s] unexpected webserver response: %q", label, body)
		}
		if !strings.Contains(body, "from "+wantSrc) {
			step.End(fmt.Errorf("[%s] expected source %q in response, got %q", label, wantSrc, body))
			t.Fatalf("[%s] expected source %q in response, got %q", label, wantSrc, body)
		}
		step.End(nil)
	}

	// accept-routes=on (set by ApproveRoutes): traffic flows via the subnet router.
	check(checkOn1Step, "accept-routes=on", routerWAN)

	// accept-routes=off: client dials the webserver directly.
	env.SetAcceptRoutes(client, false)
	check(checkOffStep, "accept-routes=off", clientWAN)

	// Toggle back on to confirm the transition works in both directions.
	env.SetAcceptRoutes(client, true)
	check(checkOn2Step, "accept-routes=on (again)", routerWAN)
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

	// Declare test-specific steps for the web UI.
	approveStep := env.AddStep("Approve subnet & exit routes")

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	tests := []struct {
		name    string // subtest name; describes (exit, subnet) toggles
		exit    *vmtest.Node
		subnet  bool
		wantSrc string
		step    *vmtest.Step
	}{
		{"exit-off,subnet-off", nil, false, clientWAN, nil},
		{"exit-off,subnet-on", nil, true, routerWAN, nil},
		{"exit-on,subnet-off", exit, false, exitWAN, nil},
		// More-specific 5.0.0.0/24 from sr beats 0.0.0.0/0 from exit.
		{"exit-on,subnet-on", exit, true, routerWAN, nil},
	}
	for i := range tests {
		tests[i].step = env.AddStep("HTTP GET: " + tests[i].name)
	}

	env.Start()
	approveStep.Begin()
	env.ApproveRoutes(sr, webRoute)
	env.ApproveRoutes(exit, "0.0.0.0/0", "::/0")
	// Don't let the exit node itself forward via the subnet router: when the
	// client is using the exit node only, we want the exit node to egress to
	// the simulated internet directly so the webserver sees the exit's WAN.
	env.SetAcceptRoutes(exit, false)
	approveStep.End(nil)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.step.Begin()
			env.SetExitNode(client, tc.exit)
			env.SetAcceptRoutes(client, tc.subnet)
			body := env.HTTPGet(client, webURL)
			t.Logf("response: %s", body)
			if !strings.Contains(body, "Hello world I am webserver") {
				tc.step.End(fmt.Errorf("unexpected webserver response: %q", body))
				t.Fatalf("unexpected webserver response: %q", body)
			}
			if !strings.Contains(body, "from "+tc.wantSrc) {
				tc.step.End(fmt.Errorf("expected source %q in response, got %q", tc.wantSrc, body))
				t.Fatalf("expected source %q in response, got %q", tc.wantSrc, body)
			}
			tc.step.End(nil)
		})
	}
}

// TestTaildrop verifies that one Ubuntu node can send a file to another
// Ubuntu node via Taildrop, and the receiver gets the same content.
//
// Topology: two Ubuntu nodes, each behind its own EasyNAT, both joined to the
// tailnet. The sender runs `tailscale file cp` to push to the receiver's
// Tailscale IP; the receiver then runs `tailscale file get --wait` to fetch
// it.
func TestTaildrop(t *testing.T) {
	env := vmtest.New(t, vmtest.SameTailnetUser())

	senderNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.EasyNAT)
	receiverNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.EasyNAT)

	sender := env.AddNode("sender", senderNet,
		vmtest.OS(vmtest.Ubuntu2404))
	receiver := env.AddNode("receiver", receiverNet,
		vmtest.OS(vmtest.Ubuntu2404))

	// Declare test-specific steps for the web UI.
	sendStep := env.AddStep("Taildrop send (sender -> receiver)")
	recvStep := env.AddStep("Taildrop receive (on receiver)")
	verifyStep := env.AddStep("Verify received name and contents")

	env.Start()

	const filename = "hello.txt"
	want := []byte("hello world this is a Taildrop test\n")

	sendStep.Begin()
	env.SendTaildropFile(sender, receiver, filename, want)
	sendStep.End(nil)

	recvStep.Begin()
	gotName, gotContent := env.RecvTaildropFile(t.Context(), receiver)
	recvStep.End(nil)

	verifyStep.Begin()
	if gotName != filename {
		err := fmt.Errorf("received name = %q; want %q", gotName, filename)
		verifyStep.End(err)
		t.Error(err)
		return
	}
	if !bytes.Equal(gotContent, want) {
		err := fmt.Errorf("received content = %q; want %q", gotContent, want)
		verifyStep.End(err)
		t.Error(err)
		return
	}
	verifyStep.End(nil)
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

	// Declare test-specific steps for the web UI.
	approveStep := env.AddStep("Approve exit-node routes (exit1, exit2)")

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	tests := []struct {
		name    string // subtest name
		exit    *vmtest.Node
		wantSrc string
		step    *vmtest.Step
	}{
		{"off", nil, clientWAN, nil},
		{"exit1", exit1, exit1WAN, nil},
		{"exit2", exit2, exit2WAN, nil},
	}
	for i := range tests {
		tests[i].step = env.AddStep("HTTP GET: exit=" + tests[i].name)
	}

	env.Start()
	approveStep.Begin()
	env.ApproveRoutes(exit1, "0.0.0.0/0", "::/0")
	env.ApproveRoutes(exit2, "0.0.0.0/0", "::/0")
	approveStep.End(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.step.Begin()
			env.SetExitNode(client, tt.exit)
			body := env.HTTPGet(client, webURL)
			t.Logf("response: %s", body)
			if !strings.Contains(body, "Hello world I am webserver") {
				tt.step.End(fmt.Errorf("unexpected webserver response: %q", body))
				t.Fatalf("unexpected webserver response: %q", body)
			}
			if !strings.Contains(body, "from "+tt.wantSrc) {
				tt.step.End(fmt.Errorf("expected source %q in response, got %q", tt.wantSrc, body))
				t.Fatalf("expected source %q in response, got %q", tt.wantSrc, body)
			}
			tt.step.End(nil)
		})
	}
}

// TestDiscoKeyChange verifies that when one node's disco key rotates without
// its WireGuard node key changing, peers detect the change, tear down stale
// WireGuard session state for that peer, and re-establish the tunnel in both
// directions. This exercises the disco-key-change handling that the
// bradfitz/rm_lazy_wg branch relies on for traffic to and from a peer whose
// magicsock state has been reset.
//
// Topology: two gokrazy nodes A and B, each on its own One2OneNAT network so
// every connection between them is a direct UDP path with no port-mapping or
// filtering. With NAT effects out of the way, what we measure here is the
// speed of disco-key-change reconciliation in wgengine/magicsock alone. The
// test control server is also configured with [testcontrol.Server.AllOnline]
// (via [vmtest.AllOnline]) so the controlclient/wgengine fast paths that
// branch on Online actually fire — without that flag the test exercises
// only the offline-peer code paths, which mask separate latent issues and
// are several seconds slower.
//
// The test runs four B-side rotations followed by a TSMP ping in the
// requested direction:
//
//	rotate (LocalAPI rotate-disco-key) → ping B → A
//	rotate (LocalAPI rotate-disco-key) → ping A → B
//	restart  (SIGKILL tailscaled)      → ping B → A
//	restart  (SIGKILL tailscaled)      → ping A → B
//
// Plus an initial A→B TSMP ping with a generous 30s budget to bring up the
// WireGuard tunnel before the rotations begin (so the post-rotation pings
// measure stale-state recovery, not first-time setup). All pings are TSMP
// because TSMP traverses the actual WireGuard data plane; PingDisco only
// exercises the magicsock disco layer and would mask any stale WG session
// problems.
//
// Two rotation methods are exercised:
//
//   - LocalAPI rotate-disco-key (debug action): rolls B's magicsock disco
//     private key in place, then bounces WantRunning to force wgengine to
//     drop wireguard-go session keys for every peer (RotateDiscoKey alone
//     only touches local disco state; without the WantRunning bounce, B
//     keeps using stale per-peer session keys against A and A drops
//     everything until B's WG rekey timer eventually fires).
//   - SIGKILL of tailscaled (via TTA's /kill-tailscaled): the gokrazy
//     supervisor respawns tailscaled, fully resetting B's magicsock and
//     wgengine state in addition to rotating the disco key.
//
// Each post-rotation ping currently gets a 15-second budget. On a
// hypothetical perfect build it should take well under a second. In
// practice today there are two unavoidable multi-second waits:
//
//   - The rotate-then-a→b phase on main takes ~10s for LazyWG. After
//     B's WantRunning bounce, B's wgengine resets its sentActivityAt/
//     recvActivityAt maps and trims A out of the wireguard-go config
//     as an "idle peer"; B only re-adds A on inbound activity, by
//     which point A's first few TSMP packets have been silently
//     dropped at B's tundev. The bradfitz/rm_lazy_wg branch removes
//     that trimming entirely (verified locally), so this phase will
//     drop to <100ms once that branch lands.
//
//   - The restart phases take ~5s for the wireguard-go handshake retry
//     timer. After SIGKILL+respawn the first WG handshake init from
//     the restarted node sometimes goes into the void (likely the
//     brief peer-removed window in the receiver's two-step
//     [wgengine.userspaceEngine.maybeReconfigWireguardLocked] reconfig
//     during which the peer is absent from wireguard-go), and wg-go's
//     [device.RekeyTimeout] of 5s + jitter is the next opportunity to
//     retry. That retry succeeds and the staged TSMP packet flushes.
//     This is intrinsic to the protocol's retransmit policy.
//
// Once LazyWG is removed and the first-handshake-after-reconfig race
// is fixed, this budget should be tightened to 5s (or less).
//
// All four rotations also assert that B's WireGuard node key is unchanged.
func TestDiscoKeyChange(t *testing.T) {
	// AllOnline makes the test control server mark every peer as Online=true
	// in its MapResponses. Several disco-key handling fast paths
	// (controlclient.removeUnwantedDiscoUpdates,
	// removeUnwantedDiscoUpdatesFromFullNetmapUpdate, and the wgengine
	// tsmpLearnedDisco fast path) only fire for online peers. Production
	// control servers always populate Online; without this flag the test
	// would only exercise the offline-peer paths.
	env := vmtest.New(t, vmtest.AllOnline())

	// One2OneNAT so each node has a 1:1 mapping to a public WAN IP with no
	// port-translation or address-port filtering. This makes A↔B traffic
	// behave like two unfirewalled hosts on the public internet, so any
	// slowness we observe in this test cannot be blamed on NAT traversal.
	aNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.One2OneNAT)
	bNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.One2OneNAT)

	a := env.AddNode("a", aNet, vmtest.OS(vmtest.Gokrazy))
	b := env.AddNode("b", bNet, vmtest.OS(vmtest.Gokrazy))

	type phase struct {
		name      string
		rotate    func()
		pingFrom  *vmtest.Node
		pingTo    *vmtest.Node
		applyStep *vmtest.Step
		verify    *vmtest.Step
		wait      *vmtest.Step
		ping      *vmtest.Step
	}
	phases := []*phase{
		{name: "rotate (LocalAPI), b → a", pingFrom: b, pingTo: a, rotate: func() { env.RotateDiscoKey(b) }},
		{name: "rotate (LocalAPI), a → b", pingFrom: a, pingTo: b, rotate: func() { env.RotateDiscoKey(b) }},
		{name: "restart, b → a", pingFrom: b, pingTo: a, rotate: func() { env.RestartTailscaled(b) }},
		{name: "restart, a → b", pingFrom: a, pingTo: b, rotate: func() { env.RestartTailscaled(b) }},
	}

	pingABStep := env.AddStep("Ping a → b TSMP (establish tunnel)")
	for _, p := range phases {
		p.applyStep = env.AddStep("Apply: " + p.name)
		p.verify = env.AddStep("Verify b: same node key, new disco key (" + p.name + ")")
		p.wait = env.AddStep("Wait for a to see b's new disco key (" + p.name + ")")
		p.ping = env.AddStep("Ping " + p.pingFrom.Name() + " → " + p.pingTo.Name() + " TSMP (" + p.name + ")")
	}

	env.Start()

	pingABStep.Begin()
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		pingABStep.End(err)
		t.Fatal(err)
	}
	pingABStep.End(nil)

	bStInitial := env.Status(b)
	bNodeKey := bStInitial.Self.PublicKey
	cs := env.ControlServer()
	bCtlNode := cs.Node(bNodeKey)
	if bCtlNode == nil {
		t.Fatalf("control server has no node for b's key %v", bNodeKey)
	}
	prevDisco := bCtlNode.DiscoKey
	if prevDisco.IsZero() {
		t.Fatalf("control server has no disco key for b before rotation")
	}
	t.Logf("[b] initial: nodekey=%s discokey=%s", bNodeKey.ShortString(), prevDisco.ShortString())

	for _, p := range phases {
		p.applyStep.Begin()
		p.rotate()
		p.applyStep.End(nil)
		prevDisco = checkDiscoRotated(t, env, a, b, p.pingFrom, p.pingTo, bNodeKey, prevDisco, p.name,
			p.verify, p.wait, p.ping)
	}
}

// checkDiscoRotated verifies that after some action that should have rotated
// b's disco key, control has learned the new key, b's node key is unchanged,
// a's local view picks up the new disco key, and pingFrom can ping pingTo
// (TSMP) within the budget. It returns b's new disco key and fatals on
// failure.
//
// The TSMP ping budget is 15 seconds rather than the few hundred ms it
// ought to take. See the top-level test docstring for a full breakdown:
// it has to absorb LazyWG's trim+re-add for the rotate-a→b phase (~10s)
// and wireguard-go's RekeyTimeout retry for the SIGKILL+restart phases
// (~5s). Tighten this once both are addressed.
func checkDiscoRotated(t *testing.T, env *vmtest.Env, a, b, pingFrom, pingTo *vmtest.Node, bNodeKey key.NodePublic, oldDisco key.DiscoPublic, label string, verifyStep, waitStep, pingStep *vmtest.Step) key.DiscoPublic {
	t.Helper()
	cs := env.ControlServer()

	verifyStep.Begin()
	bSt := env.Status(b)
	if got := bSt.Self.PublicKey; got != bNodeKey {
		err := fmt.Errorf("[%s] b's node key changed: %v -> %v", label, bNodeKey, got)
		verifyStep.End(err)
		t.Fatal(err)
	}
	var newDisco key.DiscoPublic
	if err := tstest.WaitFor(15*time.Second, func() error {
		n := cs.Node(bNodeKey)
		if n == nil {
			return fmt.Errorf("control server has no node for b")
		}
		if n.DiscoKey.IsZero() || n.DiscoKey == oldDisco {
			return fmt.Errorf("control still has old disco key %v for b", n.DiscoKey)
		}
		newDisco = n.DiscoKey
		return nil
	}); err != nil {
		verifyStep.End(err)
		t.Fatalf("[%s] %v", label, err)
	}
	t.Logf("[b] after %s: nodekey=%s discokey=%s", label, bNodeKey.ShortString(), newDisco.ShortString())
	verifyStep.End(nil)

	waitStep.Begin()
	if err := tstest.WaitFor(30*time.Second, func() error {
		d, ok, err := env.PeerDiscoKey(a, bNodeKey)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("a doesn't yet have b in its status")
		}
		if d != newDisco {
			return fmt.Errorf("a still sees b's old disco %v, want %v", d.ShortString(), newDisco.ShortString())
		}
		return nil
	}); err != nil {
		waitStep.End(err)
		env.DumpStatus(a)
		t.Fatalf("[%s] %v", label, err)
	}
	waitStep.End(nil)

	pingStep.Begin()
	t0 := time.Now()
	if err := env.Ping(pingFrom, pingTo, tailcfg.PingTSMP, 15*time.Second); err != nil {
		pingStep.End(err)
		env.DumpStatus(a)
		env.DumpStatus(b)
		t.Fatalf("[%s] %v", label, err)
	}
	t.Logf("[%s] ping %s -> %s succeeded in %v", label, pingFrom.Name(), pingTo.Name(), time.Since(t0).Round(100*time.Millisecond))
	pingStep.End(nil)
	return newDisco
}

// TestMullvadExitNode verifies that a Tailscale client whose netmap contains
// a plain-WireGuard exit node (the way Mullvad exit nodes are wired up by
// the control plane) can route internet traffic through it, with the source
// IP rewritten to the per-client Mullvad-assigned address.
//
// Topology:
//
//	client (Tailscale, gokrazy)         — clientNet (EasyNAT)     WAN 1.0.0.1
//	mullvad (Ubuntu, userspace WG)      — mullvadNet (One2OneNAT) WAN 2.0.0.1
//	webserver (no Tailscale, gokrazy)   — webNet     (One2OneNAT) WAN 5.0.0.1
//
// The mullvad VM impersonates a Mullvad WireGuard server. After boot, the
// test asks its TTA agent to bring up a userspace WireGuard interface (a
// real Linux TUN driven by wireguard-go) that pins the client's Tailscale
// node public key as its only allowed peer, sets up IP-forwarding + a
// MASQUERADE rule, and reports the WG server's freshly generated public
// key back. Userspace vs kernel WireGuard makes no difference on the wire
// — what's being tested is Tailscale's plain-WireGuard exit-node code
// path, not the kernel module.
//
// The test then injects a netmap peer with IsWireGuardOnly=true,
// AllowedIPs=[gw/32, 0.0.0.0/0, ::/0], the WG endpoint, and a per-client
// SelfNodeV4MasqAddrForThisPeer (the mock equivalent of the per-client IP
// Mullvad's API hands out at registration time).
//
// The webserver echoes the source IP it sees:
//   - exit-node off:  source is client's WAN  (direct egress)
//   - exit-node on:   source is mullvad's WAN (egress via WG + MASQUERADE)
func TestMullvadExitNode(t *testing.T) {
	env := vmtest.New(t)

	const (
		clientWAN  = "1.0.0.1"
		mullvadWAN = "2.0.0.1"
		webWAN     = "5.0.0.1"
	)
	// Mullvad-side WG network. The client appears as clientMasqIP to
	// mullvad's wg0; mullvad terminates the tunnel at gw.
	var (
		mullvadWGNet = netip.MustParsePrefix("10.64.0.0/24")
		gw           = netip.MustParsePrefix("10.64.0.1/24")
		clientMasq   = netip.MustParsePrefix("10.64.0.2/32")
	)
	const wgListenPort uint16 = 51820

	clientNet := env.AddNetwork(clientWAN, "192.168.1.1/24", vnet.EasyNAT)
	mullvadNet := env.AddNetwork(mullvadWAN, "192.168.2.1/24", vnet.One2OneNAT)
	webNet := env.AddNetwork(webWAN, "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet, vmtest.OS(vmtest.Gokrazy))
	mullvad := env.AddNode("mullvad", mullvadNet,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.DontJoinTailnet())
	env.AddNode("webserver", webNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	// Declare test-specific steps for the web UI.
	wgUpStep := env.AddStep("Bring up Mullvad WG server")
	injectStep := env.AddStep("Inject Mullvad netmap peer")
	checkOff1Step := env.AddStep("HTTP GET (exit off)")
	checkMullvadStep := env.AddStep("HTTP GET (exit=mullvad)")
	checkOff2Step := env.AddStep("HTTP GET (exit off, again)")

	env.Start()

	// Bring up the WG server inside mullvad's TTA, pinning the client's
	// Tailscale node public key as the sole allowed peer.
	wgUpStep.Begin()
	clientStatus := env.Status(client)
	mullvadPub := env.BringUpMullvadWGServer(mullvad,
		gw, wgListenPort,
		clientStatus.Self.PublicKey, clientMasq, mullvadWGNet)
	wgUpStep.End(nil)

	// Inject the mullvad node into the netmap as a plain-WireGuard exit
	// node. This mirrors how the control plane describes Mullvad exit
	// nodes to clients (see control/cmullvad in the closed repo): a
	// peer with IsWireGuardOnly=true, an Endpoints entry pointing at
	// the public WG host:port, and AllowedIPs covering both the gateway
	// /32 and the 0.0.0.0/0+::/0 exit-node routes.
	injectStep.Begin()
	mullvadEndpoint := netip.AddrPortFrom(netip.MustParseAddr(mullvadWAN), wgListenPort)
	gwHost := netip.PrefixFrom(gw.Addr(), gw.Addr().BitLen())
	mullvadNode := &tailcfg.Node{
		ID:                999_001,
		StableID:          "mullvad-test",
		Name:              "mullvad-test.fake-control.example.net.",
		Key:               mullvadPub,
		MachineAuthorized: true,
		IsWireGuardOnly:   true,
		Endpoints:         []netip.AddrPort{mullvadEndpoint},
		Addresses:         []netip.Prefix{gwHost},
		AllowedIPs: []netip.Prefix{
			gwHost,
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
		Hostinfo: (&tailcfg.Hostinfo{
			Hostname: "mullvad-test",
		}).View(),
	}
	cs := env.ControlServer()
	cs.UpdateNode(mullvadNode)

	// Set the per-peer source-IP masquerade. The control plane normally
	// derives this from the Mullvad API's per-client registration; here
	// we just pin it to the address mullvad's wg0 was told to accept.
	cs.SetMasqueradeAddresses([]testcontrol.MasqueradePair{{
		Node:              clientStatus.Self.PublicKey,
		Peer:              mullvadPub,
		NodeMasqueradesAs: clientMasq.Addr(),
	}})
	injectStep.End(nil)

	webURL := fmt.Sprintf("http://%s:8080/", webWAN)
	check := func(step *vmtest.Step, label, wantSrc string) {
		t.Helper()
		step.Begin()
		body := env.HTTPGet(client, webURL)
		t.Logf("[%s] response: %s", label, body)
		if !strings.Contains(body, "Hello world I am webserver") {
			step.End(fmt.Errorf("[%s] unexpected webserver response: %q", label, body))
			t.Fatalf("[%s] unexpected webserver response: %q", label, body)
		}
		if !strings.Contains(body, "from "+wantSrc) {
			step.End(fmt.Errorf("[%s] expected source %q in response, got %q", label, wantSrc, body))
			t.Fatalf("[%s] expected source %q in response, got %q", label, wantSrc, body)
		}
		step.End(nil)
	}

	// Exit-node off: client routes 0.0.0.0/0 directly via its host stack,
	// so the webserver sees client's WAN IP.
	check(checkOff1Step, "exit-off", clientWAN)

	// Switch to the Mullvad WG-only peer as exit node. The client should
	// now route 0.0.0.0/0 through the WG tunnel; mullvad MASQUERADEs to
	// its WAN; the webserver sees the mullvad VM's WAN IP.
	env.SetExitNodeIP(client, gw.Addr())
	check(checkMullvadStep, "exit-mullvad", mullvadWAN)

	// And back off again, to make sure the transition works in both
	// directions.
	env.SetExitNodeIP(client, netip.Addr{})
	check(checkOff2Step, "exit-off (again)", clientWAN)
}

// TestCachedNetmapAfterRestart verifies that two nodes with netmap
// caching enabled (NodeAttrCacheNetworkMaps) can re-establish a direct
// WireGuard tunnel after both are restarted while the control server is
// unreachable. After restart the nodes must use only their on-disk cached
// netmaps to re-connect.
func TestCachedNetmapAfterRestart(t *testing.T) {
	env := vmtest.New(t)

	aNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.EasyNAT)
	bNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.EasyNAT)

	aNet.SetPostConnectControlBlackhole(true)
	bNet.SetPostConnectControlBlackhole(true)

	a := env.AddNode("a", aNet,
		vmtest.OS(vmtest.Gokrazy),
		tailcfg.NodeCapMap{tailcfg.NodeAttrCacheNetworkMaps: nil})
	b := env.AddNode("b", bNet,
		vmtest.OS(vmtest.Gokrazy),
		tailcfg.NodeCapMap{tailcfg.NodeAttrCacheNetworkMaps: nil})

	connectStep := env.AddStep("Establish initial TSMP tunnel")
	cutControlStep := env.AddStep("Cut control server access")
	restartStep := env.AddStep("Restart tailscaled on both nodes")
	netmapCheckStep := env.AddStep("Check netmap loaded is cached")
	pingStep := env.AddStep("Ping a → b TSMP (cached netmap, no control)")

	env.Start()

	connectStep.Begin()
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		connectStep.End(err)
		t.Fatal(err)
	}
	connectStep.End(nil)

	cutControlStep.Begin()
	aNet.PostConnectedToControl()
	bNet.PostConnectedToControl()
	env.ControlServer().SetOnMapRequest(func(nk key.NodePublic) {
		panic(fmt.Sprintf("got connection from %v", nk))
	})
	cutControlStep.End(nil)

	restartStep.Begin()
	env.RestartTailscaled(a)
	env.RestartTailscaled(b)
	restartStep.End(nil)

	netmapCheckStep.Begin()
	for _, node := range []*vmtest.Node{a, b} {
		nm, err := local.GetDebugResultJSON[netmap.NetworkMap](t.Context(), node.Agent().Client, "current-netmap")
		if err != nil {
			netmapCheckStep.End(fmt.Errorf("[%s] got err fetching netmap %q", node.Name(), err))
			t.Fatalf("[%s] got err fetching netmap %q", node.Name(), err)
		}
		if !nm.Cached {
			netmapCheckStep.End(fmt.Errorf("[%s] expected netmap.Cached = true, got: %t", node.Name(), nm.Cached))
			t.Fatalf("[%s] expected netmap.Cached = true, got: %t", node.Name(), nm.Cached)
		}
	}
	netmapCheckStep.End(nil)

	pingStep.Begin()
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		pingStep.End(err)
		t.Fatal(err)
	}
	pingStep.End(nil)
}
