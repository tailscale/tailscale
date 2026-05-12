// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"flag"
	"fmt"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

var knownBroken = flag.Bool("known-broken", false, "run known-broken tests")

func v6cidr(n int) string {
	return fmt.Sprintf("2000:%d::1/64", n)
}

func easy(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

func easyAnd6(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n),
			v6cidr(n),
			vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

// easyNoControlDiscoRotate sets up a node with easy NAT, cuts traffic to
// control after connecting, and then rotates the disco key to simulate a newly
// started node (from a disco perspective).
func easyNoControlDiscoRotate(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	nw := env.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
		fmt.Sprintf("192.168.%d.1/24", n),
		vnet.EasyNAT)
	nw.SetPostConnectControlBlackhole(true)
	return env.AddNode(fmt.Sprintf("node-%d", n),
		vnet.TailscaledEnv{Key: "TS_USE_CACHED_NETMAP", Value: "true"},
		vnet.RotateDisco, vnet.PreICMPPing,
		nw,
		vmtest.OS(vmtest.Gokrazy))
}

// easyFW is easy + host firewall.
func easyFW(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

// easyPMPFWPlusBPF is easy + port mapping + host firewall + BPF.
func easyPMPFWPlusBPF(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		vnet.TailscaledEnv{Key: "TS_ENABLE_RAW_DISCO", Value: "true"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_RAW_DISCO", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_DISCO", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_LOG_VERBOSITY", Value: "2"},
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP),
		vmtest.OS(vmtest.Gokrazy))
}

// easyPMPFWNoBPF is easy + port mapping + host firewall - BPF.
func easyPMPFWNoBPF(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		vnet.TailscaledEnv{Key: "TS_ENABLE_RAW_DISCO", Value: "false"},
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP),
		vmtest.OS(vmtest.Gokrazy))
}

func hard(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT),
		vmtest.OS(vmtest.Gokrazy))
}

func hardNoDERPOrEndpoints(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT),
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_ENDPOINTS", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_HOME_DERP", Value: "1"},
		vmtest.OS(vmtest.Gokrazy))
}

func just6(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(v6cidr(n)), // public IPv6 prefix
		vmtest.OS(vmtest.Gokrazy))
}

func v6AndBlackholedIPv4(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	nw := env.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n),
		fmt.Sprintf("192.168.%d.1/24", n),
		v6cidr(n),
		vnet.EasyNAT)
	nw.SetBlackholedIPv4(true)
	return env.AddNode(fmt.Sprintf("node-%d", n), nw, vmtest.OS(vmtest.Gokrazy))
}

func TestEasyEasy(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easy, easy)
}

// TestTwoEasyNoControlDiscoRotate tests a situation where two nodes have been
// online and connected through control, but then lose control access and also
// rotate keys. It is not a perfect proxy for a cached node, as the node will
// still have a mapState and not use the backup method of inserting keys into
// the engine directly.
func TestTwoEasyNoControlDiscoRotate(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easyNoControlDiscoRotate, easyNoControlDiscoRotate)
}

func TestJustIPv6(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, just6, just6)
}

func TestEasy4AndJust6(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easyAnd6, just6)
}

func TestSameLAN(t *testing.T) {
	env := vmtest.New(t)
	var sharedNW *vnet.Network
	makeEasy := func(env *vmtest.Env) *vmtest.Node {
		n := env.NumNodes()
		sharedNW = env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT)
		return env.AddNode(fmt.Sprintf("node-%d", n), sharedNW, vmtest.OS(vmtest.Gokrazy))
	}
	sameLAN := func(env *vmtest.Env) *vmtest.Node {
		n := env.NumNodes()
		return env.AddNode(fmt.Sprintf("node-%d", n), sharedNW, vmtest.OS(vmtest.Gokrazy))
	}
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteLocal, makeEasy, sameLAN)
}

// TestBPFDisco tests https://github.com/tailscale/tailscale/issues/3824 ...
// * server behind a Hard NAT
// * client behind a NAT with UPnP support
// * client machine has a stateful host firewall (e.g. ufw)
func TestBPFDisco(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easyPMPFWPlusBPF, hard)
}

func TestHostFWNoBPF(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDERP, easyPMPFWNoBPF, hard)
}

func TestHostFWPair(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easyFW, easyFW)
}

func TestOneHostFW(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDirect, easy, easyFW)
}

// Issue tailscale/corp#26438: use learned DERP route as send path of last
// resort
//
// See (*magicsock.Conn).fallbackDERPRegionForPeer and its comment for
// background.
//
// This sets up a test with two nodes that must use DERP to communicate but the
// target of the ping (the second node) additionally is not getting DERP or
// Endpoint updates from the control plane. (Or rather, it's getting them but is
// configured to scrub them right when they come off the network before being
// processed) This then tests whether node2, upon receiving a packet, will be
// able to reply to node1 since it knows neither node1's endpoints nor its home
// DERP. The only reply route it can use is that fact that it just received a
// packet over a particular DERP from that peer.
func TestFallbackDERPRegionForPeer(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTest(t.Name(), vmtest.PingRouteDERP, hard, hardNoDERPOrEndpoints)
}

// TestSingleJustIPv6 tests that a node can connect to control with just IPv6.
// Since there is no connectivity testing needed, the test just asserts the
// node coming up which will be asserted by env.Start().
func TestSingleJustIPv6(t *testing.T) {
	env := vmtest.New(t)
	just6(env)
	env.Start()
}

// TestSingleDualBrokenIPv4 tests a dual-stack node with broken
// (blackholed) IPv4.
//
// See https://github.com/tailscale/tailscale/issues/13346
func TestSingleDualBrokenIPv4(t *testing.T) {
	if !*knownBroken {
		t.Skip("skipping known-broken test; set --known-broken to run; see https://github.com/tailscale/tailscale/issues/13346")
	}
	env := vmtest.New(t)
	v6AndBlackholedIPv4(env)
	env.Start()
}

func TestNonTailscaleCGNATEndpoint(t *testing.T) {
	env := vmtest.New(t)

	cgnatNW := env.AddNetwork("100.65.1.1/16", "2.1.1.1", vnet.EasyNAT)
	n0 := env.AddNode("node-0",
		cgnatNW,
		vmtest.DontJoinTailnet(),
		vmtest.OS(vmtest.Gokrazy))
	n1 := env.AddNode("node-1",
		cgnatNW,
		tailcfg.NodeCapMap{tailcfg.NodeAttrDisableLinuxCGNATDropRule: nil},
		vmtest.OS(vmtest.Gokrazy))

	env.Start()
	env.LANPing(n1, n0.LanIP(cgnatNW))
}
