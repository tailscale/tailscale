// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"cmp"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

func v6cidr(n int) string {
	return fmt.Sprintf("2000:%d::1/64", n)
}

func easy(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

func easyAF(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyAFNAT))
}

func easyAnd6(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n),
			v6cidr(n),
			vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

// easyFW is easy + host firewall.
func easyFW(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))
}

// easyPMPFWPlusBPF is easy + port mapping + host firewall + BPF.
func easyPMPFWPlusBPF(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		vnet.TailscaledEnv{Key: "TS_ENABLE_RAW_DISCO", Value: "true"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_RAW_DISCO", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_DISCO", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_LOG_VERBOSITY", Value: "2"},
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP),
		vmtest.OS(vmtest.Gokrazy))
}

// easyPMPFWNoBPF is easy + port mapping + host firewall - BPF.
func easyPMPFWNoBPF(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		vnet.HostFirewall,
		vnet.TailscaledEnv{Key: "TS_ENABLE_RAW_DISCO", Value: "false"},
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP),
		vmtest.OS(vmtest.Gokrazy))
}

func hard(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT),
		vmtest.OS(vmtest.Gokrazy))
}

func easyPMP(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT, vnet.NATPMP))
}

func hardPMP(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.7.%d.1/24", n), vnet.HardNAT, vnet.NATPMP))
}

func hardNoDERPOrEndpoints(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT),
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_ENDPOINTS", Value: "1"},
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_HOME_DERP", Value: "1"},
		vmtest.OS(vmtest.Gokrazy))
}

func one2one(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("172.16.%d.1/24", n), vnet.One2OneNAT))
}

func sameLAN(e *vmtest.Env) *vmtest.Node {
	nw := e.FirstNetwork()
	if nw == nil {
		return nil
	}
	if !nw.CanTakeMoreNodes() {
		return nil
	}
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n), nw)
}

func cgnat(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(
			fmt.Sprintf("100.65.%d.1/16", n),
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			vnet.EasyNAT))
}

func just6(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	return e.AddNode(fmt.Sprintf("node-%d", n),
		e.AddNetwork(v6cidr(n)), // public IPv6 prefix
		vmtest.OS(vmtest.Gokrazy))
}

func v6AndBlackholedIPv4(e *vmtest.Env) *vmtest.Node {
	n := e.NumNodes()
	nw := e.AddNetwork(
		fmt.Sprintf("2.%d.%d.%d", n, n, n),
		fmt.Sprintf("192.168.%d.1/24", n),
		v6cidr(n),
		vnet.EasyNAT)
	nw.SetBlackholedIPv4(true)
	return e.AddNode(fmt.Sprintf("node-%d", n), nw, vmtest.OS(vmtest.Gokrazy))
}

func TestEasyEasy(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, easy, easy)
}

func TestJustIPv6(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, just6, just6)
}

func TestEasy4AndJust6(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, easyAnd6, just6)
}

func TestSameLAN(t *testing.T) {
	env := vmtest.New(t)
	var sharedNW *vnet.Network
	makeEasy := func(e *vmtest.Env) *vmtest.Node {
		n := e.NumNodes()
		sharedNW = e.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT)
		return e.AddNode(fmt.Sprintf("node-%d", n), sharedNW, vmtest.OS(vmtest.Gokrazy))
	}
	sameLAN := func(e *vmtest.Env) *vmtest.Node {
		n := e.NumNodes()
		return e.AddNode(fmt.Sprintf("node-%d", n), sharedNW, vmtest.OS(vmtest.Gokrazy))
	}
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteLocal, makeEasy, sameLAN)
}

// TestBPFDisco tests https://github.com/tailscale/tailscale/issues/3824 ...
// * server behind a Hard NAT
// * client behind a NAT with UPnP support
// * client machine has a stateful host firewall (e.g. ufw)
func TestBPFDisco(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, easyPMPFWPlusBPF, hard)
}

func TestHostFWNoBPF(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDERP, easyPMPFWNoBPF, hard)
}

func TestHostFWPair(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, easyFW, easyFW)
}

func TestOneHostFW(t *testing.T) {
	env := vmtest.New(t)
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDirect, easy, easyFW)
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
	env.RunConnectivityTestExpect(t.Name(), vmtest.PingRouteDERP, hard, hardNoDERPOrEndpoints)
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
func TestSingleDualBrokenIPv4(t *testing.T) {
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
		tailcfg.NodeCapMap{nodecap.DisableLinuxCGNATDropRule: nil},
		vmtest.OS(vmtest.Gokrazy))

	env.Start()
	env.LANPing(n1, n0.LanIP(cgnatNW))
}

type nodeType struct {
	name string
	fn   vmtest.AddNodeFunc
}

var types = []nodeType{
	{"easy", easy},
	{"easyAF", easyAF},
	{"hard", hard},
	{"easyPMP", easyPMP},
	{"hardPMP", hardPMP},
	{"one2one", one2one},
	{"sameLAN", sameLAN},
	{"cgnat", cgnat},
}

var pair = flag.String("pair", "", "comma-separated pair of types to test (easy, easyAF, hard, easyPMP, hardPMP, one2one, sameLAN)")

func TestPair(t *testing.T) {
	t1, t2, ok := strings.Cut(*pair, ",")
	if !ok {
		t.Skipf("skipping test without --pair=type1,type2 set")
	}
	find := func(name string) vmtest.AddNodeFunc {
		for _, nt := range types {
			if nt.name == name {
				return nt.fn
			}
		}
		t.Fatalf("unknown type %q", name)
		return nil
	}

	env := vmtest.New(t)
	route := env.RunConnectivityTest(t.Name(), find(t1), find(t2))
	t.Logf("pair: got ping route: %s", route)
}

var runGrid = flag.Bool("run-grid", false, "run grid test")

func TestGrid(t *testing.T) {
	if !*runGrid {
		t.Skip("skipping grid test; set --run-grid to run")
	}
	t.Parallel()

	sem := syncs.NewSemaphore(2)
	var (
		mu  sync.Mutex
		res = make(map[string]vmtest.PingRoute)
	)
	for _, a := range types {
		for _, b := range types {
			key := a.name + "-" + b.name
			keyBack := b.name + "-" + a.name
			t.Run(key, func(t *testing.T) {
				t.Parallel()

				sem.Acquire()
				defer sem.Release()

				filename := key + ".cache"
				contents, _ := os.ReadFile(filename)
				if len(contents) == 0 {
					filename2 := keyBack + ".cache"
					contents, _ = os.ReadFile(filename2)
				}
				route := vmtest.PingRoute(strings.TrimSpace(string(contents)))

				if route == "" {
					env := vmtest.New(t)
					route = env.RunConnectivityTest(
						fmt.Sprintf("%s<->%s", a.name, b.name), a.fn, b.fn)
					if err := os.WriteFile(filename, []byte(string(route)), 0o666); err != nil {
						t.Fatalf("writeFile: %v", err)
					}
				}

				mu.Lock()
				defer mu.Unlock()
				res[key] = route
				t.Logf("results: %v", res)
			})
		}
	}

	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		var hb bytes.Buffer
		pf := func(format string, args ...any) {
			fmt.Fprintf(&hb, format, args...)
		}
		rewrite := func(s string) string {
			return strings.ReplaceAll(s, "PMP", "+pm")
		}
		pf("<html><table border=1 cellpadding=5>")
		pf("<tr><td></td>")
		for _, a := range types {
			pf("<td><b>%s</b></td>", rewrite(a.name))
		}
		pf("</tr>\n")

		for _, a := range types {
			if a.name == "sameLAN" {
				continue
			}
			pf("<tr><td><b>%s</b></td>", rewrite(a.name))
			for _, b := range types {
				key := a.name + "-" + b.name
				key2 := b.name + "-" + a.name
				v := cmp.Or(res[key], res[key2], "-")
				if v == "derp" {
					pf("<td><div style='color: red; font-weight: bold'>%s</div></td>", v)
				} else if v == "local" {
					pf("<td><div style='color: green; font-weight: bold'>%s</div></td>", v)
				} else {
					pf("<td>%s</td>", v)
				}
			}
			pf("</tr>\n")
		}
		pf("</table>")
		pf("<b>easy</b>: Endpoint-Independent Mapping, Address and Port-Dependent Filtering (e.g. Linux, Google Wifi, Unifi, eero)<br>")
		pf("<b>easyAF</b>: Endpoint-Independent Mapping, Address-Dependent Filtering (James says telephony things or Zyxel type things)<br>")
		pf("<b>hard</b>: Address and Port-Dependent Mapping, Address and Port-Dependent Filtering (FreeBSD, OPNSense, pfSense)<br>")
		pf("<b>one2one</b>: One-to-One NAT (e.g. an EC2 instance with a public IPv4)<br>")
		pf("<b>x+pm</b>: x, with port mapping (NAT-PMP, PCP, UPnP, etc)<br>")
		pf("<b>sameLAN</b>: a second node in the same LAN as the first<br>")
		pf("</html>")

		if err := os.WriteFile("grid.html", hb.Bytes(), 0o666); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	})
}
