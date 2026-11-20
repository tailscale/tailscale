// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestExitNodeStrictRPFilter is an end-to-end test of using an exit node on
// a Linux client with strict reverse path filtering (rp_filter=1) and
// src_valid_mark=0, with real packets. See tailscale/tailscale#3310 and
// #19796.
//
// Without the router's rp_filter underlay rules, the kernel drops replies to
// tailscaled's own sockets as martians once table 52 holds the exit node's
// default route, so direct UDP paths (to the exit node, and to peers on the
// LAN) stop working. The earlier workaround (#19537) set
// net.ipv4.conf.all.src_valid_mark=1, which broke other fwmark users
// (#19796); the router now uses ip rules instead and must leave
// src_valid_mark alone.
//
// Topology:
//
//	clientNet (LAN, EasyNAT): client (Ubuntu), control (Ubuntu), lanpeer (gokrazy)
//	exitNet   (EasyNAT):      exit (gokrazy), advertising 0.0.0.0/0 and ::/0
//	webNet    (One2OneNAT):   web (gokrazy, not on the tailnet), an Internet host
//
// The control node is identical to the client but runs with the rules
// disabled (TS_DEBUG_DISABLE_RPFILTER_SRC_RULES), proving the topology
// reproduces the bug.
//
// SSH into the Ubuntu nodes uses a separate QEMU user-mode NIC, whose subnet
// ipnlocal treats as a LAN. With ExitNodeAllowLANAccess off, table 52 claims
// it and replies to SSH go into the tunnel, so SSH checks happen while LAN
// access is on (phase A); the LAN-access-off checks (phase B) go through the
// test agent only.
func TestExitNodeStrictRPFilter(t *testing.T) {
	env := vmtest.New(t)

	clientNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.EasyNAT)
	exitNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.EasyNAT)
	webNet := env.AddNetwork("5.0.0.100", "192.168.5.1/24", vnet.One2OneNAT)

	client := env.AddNode("client", clientNet, vmtest.OS(vmtest.Ubuntu2404))
	control := env.AddNode("control", clientNet, vmtest.OS(vmtest.Ubuntu2404),
		vnet.TailscaledEnv{Key: "TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", Value: "true"})
	lanpeer := env.AddNode("lanpeer", clientNet, vmtest.OS(vmtest.Gokrazy))
	exit := env.AddNode("exit", exitNet, vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes("0.0.0.0/0,::/0"))
	env.AddNode("web", webNet, vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	setupStep := env.AddStep("Approve exit node; strict rp_filter on client and control")
	phaseAStep := env.AddStep("Exit node, LAN access on: client works, control reproduces #3310")
	phaseBStep := env.AddStep("Exit node, LAN access off: direct paths to exit node and LAN peer")
	cleanupStep := env.AddStep("Exit node off: rules removed, src_valid_mark untouched")

	env.Start()

	const webURL = "http://5.0.0.100:8080/"
	const exitWAN = "2.0.0.1"
	ssh := func(n *vmtest.Node, cmd string) string {
		t.Helper()
		out, err := env.SSHExec(n, cmd)
		if err != nil {
			t.Fatalf("[%s] %s: %v\n%s", n.Name(), cmd, err, out)
		}
		return strings.TrimSpace(out)
	}
	rpDrops := func(n *vmtest.Node) int {
		t.Helper()
		out := ssh(n, `awk '/^TcpExt:/{if(!h){split($0,k);h=1}else{split($0,v);for(i in k)if(k[i]=="IPReversePathFilter")print v[i]}}' /proc/net/netstat`)
		v, err := strconv.Atoi(out)
		if err != nil {
			t.Fatalf("[%s] parsing IPReversePathFilter %q: %v", n.Name(), out, err)
		}
		return v
	}
	exitIP := func() string {
		st := env.Status(exit)
		if st == nil || len(st.Self.TailscaleIPs) == 0 {
			t.Fatalf("exit node has no Tailscale IP")
		}
		return st.Self.TailscaleIPs[0].String()
	}

	setupStep.Begin()
	env.ApproveRoutes(exit, "0.0.0.0/0", "::/0")
	for _, n := range []*vmtest.Node{client, control} {
		// Ubuntu defaults to loose mode (2). The effective mode of an
		// interface is the larger of conf/all and conf/<if>, so set all of
		// them. Set before choosing the exit node: the router checks it
		// when the config changes.
		ssh(n, `for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > "$f"; done; sysctl -qw net.ipv4.conf.all.src_valid_mark=0`)
		if got := ssh(n, "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter"); got != "1\n1" {
			setupStep.Fatalf("[%s] rp_filter = %q, want strict", n.Name(), got)
		}
		if got := ssh(n, "ip rule show | grep -c 'proto 52' || true"); got != "0" {
			setupStep.Fatalf("[%s] %s underlay rules before using an exit node", n.Name(), got)
		}
		if _, err := env.Tailscale(n, "set", "--exit-node-allow-lan-access=true"); err != nil {
			setupStep.Fatalf("[%s] allow LAN access: %v", n.Name(), err)
		}
	}
	setupStep.End(nil)

	phaseAStep.Begin()
	controlDropsBefore := rpDrops(control)
	env.SetExitNode(client, exit)
	env.SetExitNode(control, exit)

	// The client: the rules are in place, and its traffic uses the exit
	// node over a direct path.
	rules := ssh(client, "ip rule show")
	t.Logf("[client] ip rule show:\n%s", rules)
	for _, want := range []string{
		"not from all fwmark 0x80000/0xff0000 lookup 52 suppress_prefixlength 0 proto 52",
		"from 192.168.1.",
		"uidrange 0-0 lookup main proto 52",
		"ipproto udp sport ",
	} {
		if !strings.Contains(rules, want) {
			// Not fatal: the behavior checks below are what matter, and
			// should fail on their own if a rule is missing.
			t.Errorf("[client] ip rules lack %q", want)
		}
	}
	if got := ssh(client, "sysctl -n net.ipv4.conf.all.src_valid_mark"); got != "0" {
		phaseAStep.Fatalf("[client] src_valid_mark = %s, want 0 (see #19796)", got)
	}
	if ep, err := env.PingExpect(client, exit, vmtest.PingRouteDirect, 90*time.Second); err != nil {
		phaseAStep.Fatalf("[client] direct path to exit node: %v", err)
	} else {
		t.Logf("[client] direct path to exit node via %s", ep)
	}
	body := ssh(client, "curl --silent --show-error --max-time 20 "+webURL)
	if !strings.Contains(body, "from "+exitWAN) {
		phaseAStep.Fatalf("[client] web request didn't leave via the exit node (%s): %q", exitWAN, body)
	}

	// The control: no rules, and the direct path to the exit node never
	// comes up because the kernel drops the replies as martians. (Its DERP
	// connection was established before and survives: established TCP
	// sockets skip the reverse path check.)
	if got := ssh(control, "ip rule show | grep -c 'proto 52' || true"); got != "0" {
		phaseAStep.Fatalf("[control] has %s underlay rules despite the kill switch", got)
	}
	ctlPing := ssh(control, fmt.Sprintf("tailscale ping -c 10 --timeout 3s %s 2>&1 || true", exitIP()))
	t.Logf("[control] tailscale ping exit:\n%s", ctlPing)
	if strings.Contains(ctlPing, "via "+exitWAN) {
		phaseAStep.Fatalf("[control] got a direct path to the exit node without the rules; topology doesn't reproduce #3310")
	}
	if after := rpDrops(control); after <= controlDropsBefore {
		phaseAStep.Fatalf("[control] IPReversePathFilter %d -> %d; want martian drops", controlDropsBefore, after)
	} else {
		t.Logf("[control] IPReversePathFilter %d -> %d", controlDropsBefore, after)
	}
	phaseAStep.End(nil)

	phaseBStep.Begin()
	// LAN access off: table 52 claims the LAN prefixes, so this also
	// exercises the magicsock port rule (replies from the LAN peer).
	if _, err := env.Tailscale(client, "set", "--exit-node-allow-lan-access=false"); err != nil {
		phaseBStep.Fatalf("[client] disallow LAN access: %v", err)
	}
	if ep, err := env.PingExpect(client, lanpeer, vmtest.PingRouteLocal, 90*time.Second); err != nil {
		phaseBStep.Fatalf("[client] LAN path to lanpeer: %v", err)
	} else {
		t.Logf("[client] LAN path to lanpeer via %s", ep)
	}
	if _, err := env.PingExpect(client, exit, vmtest.PingRouteDirect, 90*time.Second); err != nil {
		phaseBStep.Fatalf("[client] direct path to exit node: %v", err)
	}
	if body := env.HTTPGet(client, webURL); !strings.Contains(body, "from "+exitWAN) {
		phaseBStep.Fatalf("[client] web request didn't leave via the exit node (%s): %q", exitWAN, body)
	}
	phaseBStep.End(nil)

	cleanupStep.Begin()
	env.SetExitNode(client, nil)
	// SSH works again once the exit node (and its LAN prefix routes) are
	// gone; retry briefly while the config settles.
	var got string
	for range 20 {
		if out, err := env.SSHExec(client, "ip rule show | grep -c 'proto 52' || true"); err == nil {
			got = strings.TrimSpace(out)
			if got == "0" {
				break
			}
		}
		time.Sleep(time.Second)
	}
	if got != "0" {
		cleanupStep.Fatalf("[client] %q underlay rules left after turning off the exit node", got)
	}
	if got := ssh(client, "sysctl -n net.ipv4.conf.all.src_valid_mark"); got != "0" {
		cleanupStep.Fatalf("[client] src_valid_mark = %s, want 0", got)
	}
	cleanupStep.End(nil)
}
