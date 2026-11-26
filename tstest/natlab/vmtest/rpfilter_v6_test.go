// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestExitNodeStrictRPFilterV6 is the IPv6 counterpart of
// TestExitNodeStrictRPFilter: an end-to-end test, with real packets, that the
// router's IPv6 underlay rules keep direct IPv6 paths working on a Linux
// client with a reverse path filter while it uses an exit node.
//
// IPv6 has no kernel rp_filter. Its reverse path checks are netfilter ones,
// such as firewalld's default IPv6_rpfilter, an nftables "fib saddr . iif oif
// missing drop" in raw prerouting. Once table 52 holds the exit node's ::/0,
// that lookup finds the Tailscale interface for replies to tailscaled's own
// sockets, which arrive on the physical one, and drops them. The router
// installs its IPv6 rules whatever the IPv4 rp_filter mode, so this test
// leaves IPv4 rp_filter at Ubuntu's loose default, under which the IPv4 rules
// aren't installed, and tests IPv6 alone.
//
// Topology:
//
//	clientNet (dual-stack, EasyNAT): client (Ubuntu), control (Ubuntu)
//	peerNet   (dual-stack, EasyNAT): peer (gokrazy), an ordinary tailnet node
//	exitNet   (IPv4, EasyNAT):       exit (gokrazy), advertising 0.0.0.0/0 and ::/0
//
// The direct path under test is to peer, not to the exit node: advertising
// routes enables IPv6 forwarding, which stops the kernel from accepting router
// advertisements, so an exit node here loses its IPv6 default route. Any
// Internet peer shows the bug, since ::/0 covers it. On client and control an
// output rule drops UDP to peer's IPv4 WAN address, so the only direct path
// to it is over IPv6.
//
// The control node is identical to the client but runs with the rules
// disabled (TS_DEBUG_DISABLE_RPFILTER_SRC_RULES), proving the topology
// reproduces the bug.
func TestExitNodeStrictRPFilterV6(t *testing.T) {
	env := vmtest.New(t)

	const peerWAN4, peerPrefix = "3.0.0.1", "2000:3::1/64"
	clientNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", "2000:1::1/64", vnet.EasyNAT)
	peerNet := env.AddNetwork(peerWAN4, "192.168.3.1/24", peerPrefix, vnet.EasyNAT)
	exitNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.EasyNAT)

	client := env.AddNode("client", clientNet, vmtest.OS(vmtest.Ubuntu2404))
	control := env.AddNode("control", clientNet, vmtest.OS(vmtest.Ubuntu2404),
		vnet.TailscaledEnv{Key: "TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", Value: "true"})
	peer := env.AddNode("peer", peerNet, vmtest.OS(vmtest.Gokrazy))
	exit := env.AddNode("exit", exitNet, vmtest.OS(vmtest.Gokrazy),
		vmtest.AdvertiseRoutes("0.0.0.0/0,::/0"))

	setupStep := env.AddStep("Approve exit node; IPv6 rpfilter on client and control")
	baseStep := env.AddStep("No exit node: direct IPv6 path to peer from client and control")
	exitStep := env.AddStep("Exit node: client keeps its direct IPv6 path, control loses it")
	cleanupStep := env.AddStep("Exit node off: rules removed")

	env.Start()

	peerV6Net := netip.MustParsePrefix(peerPrefix).Masked()
	ssh := func(n *vmtest.Node, cmd string) string {
		t.Helper()
		out, err := env.SSHExec(n, cmd)
		if err != nil {
			t.Fatalf("[%s] %s: %v\n%s", n.Name(), cmd, err, out)
		}
		return strings.TrimSpace(out)
	}
	// eventually polls cmd's output on n until ok accepts it. The router
	// applies a new exit node asynchronously, after SetExitNode returns, and
	// nothing on the VM can say when it's done, so its state is polled, with
	// a deadline.
	eventually := func(step *vmtest.Step, n *vmtest.Node, what, cmd string, ok func(string) bool) string {
		t.Helper()
		var out string
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
			if out = ssh(n, cmd); ok(out) {
				return out
			}
		}
		step.Fatalf("[%s] timed out waiting for %s; last output of %q:\n%s", n.Name(), what, cmd, out)
		return ""
	}
	// rpfDrops returns how many UDP packets n's IPv6 reverse path filter
	// has dropped.
	rpfDrops := func(n *vmtest.Node) int {
		t.Helper()
		out := ssh(n, "nft list chain inet natlabrpf pre")
		m := regexp.MustCompile(`counter packets (\d+) bytes \d+ drop comment "rpf-drop"`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("[%s] no rpf-drop counter in:\n%s", n.Name(), out)
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	tailscaleIP := func(n *vmtest.Node) string {
		st := env.Status(n)
		if st == nil || len(st.Self.TailscaleIPs) == 0 {
			t.Fatalf("%s has no Tailscale IP", n.Name())
		}
		return st.Self.TailscaleIPs[0].String()
	}
	// wantV6Direct waits for a direct path from n to peer and checks that
	// it's over IPv6, to peer's IPv6 WAN prefix.
	wantV6Direct := func(step *vmtest.Step, n *vmtest.Node) {
		t.Helper()
		ep, err := env.PingExpect(n, peer, vmtest.PingRouteDirect, 120*time.Second)
		if err != nil {
			step.Fatalf("[%s] direct path to peer: %v", n.Name(), err)
		}
		ap, err := netip.ParseAddrPort(ep)
		if err != nil || !peerV6Net.Contains(ap.Addr()) {
			step.Fatalf("[%s] direct path to peer via %q; want an address in %v", n.Name(), ep, peerV6Net)
		}
		t.Logf("[%s] direct path to peer via %s", n.Name(), ep)
	}

	setupStep.Begin()
	env.ApproveRoutes(exit, "0.0.0.0/0", "::/0")
	for _, n := range []*vmtest.Node{client, control} {
		if got := ssh(n, "ip -6 -o addr show dev "+vmtest.VnetNICName+" scope global"); !strings.Contains(got, "2000:1:") {
			setupStep.Fatalf("[%s] no global IPv6 address on %s: %q", n.Name(), vmtest.VnetNICName, got)
		}
		// The filter, as firewalld's IPv6_rpfilter does it, but only for
		// UDP on the vnet NIC: magicsock is what's under test, and leaving
		// TCP alone keeps the control node's control and DERP connections
		// up when it loses its direct path. The output rule makes IPv6 the
		// only direct path to peer.
		ssh(n, fmt.Sprintf(`nft -f - <<'EOF'
table inet natlabrpf {
	chain pre {
		type filter hook prerouting priority raw; policy accept;
		iifname %[1]q meta nfproto ipv6 meta l4proto udp fib saddr . iif oif missing counter drop comment "rpf-drop"
	}
	chain out {
		type filter hook output priority filter; policy accept;
		ip daddr %[2]s meta l4proto udp counter drop comment "no-v4-direct"
	}
}
EOF`, vmtest.VnetNICName, peerWAN4))
		if _, err := env.Tailscale(n, "set", "--exit-node-allow-lan-access=true"); err != nil {
			setupStep.Fatalf("[%s] allow LAN access: %v", n.Name(), err)
		}
	}
	setupStep.End(nil)

	// Without an exit node, both nodes get a direct IPv6 path to peer and
	// the filter drops nothing: it's the exit node's route, not the filter
	// alone, that breaks the control node below.
	baseStep.Begin()
	for _, n := range []*vmtest.Node{client, control} {
		wantV6Direct(baseStep, n)
		if got := rpfDrops(n); got != 0 {
			baseStep.Fatalf("[%s] rpfilter dropped %d packets without an exit node", n.Name(), got)
		}
	}
	baseStep.End(nil)

	exitStep.Begin()
	env.SetExitNode(client, exit)
	env.SetExitNode(control, exit)
	for _, n := range []*vmtest.Node{client, control} {
		eventually(exitStep, n, "the exit node's ::/0 in table 52", "ip -6 route show table 52 default", func(out string) bool {
			return strings.Contains(out, "default dev tailscale0")
		})
	}

	// The client: IPv6 rules only (IPv4 rp_filter is loose), and its
	// direct IPv6 path to peer keeps working.
	rules6 := ssh(client, "ip -6 rule show")
	t.Logf("[client] ip -6 rule show:\n%s", rules6)
	for _, want := range []string{
		"not from all fwmark 0x80000/0xff0000 lookup 52 suppress_prefixlength 0 proto 52",
		"from 2000:1:",
		"uidrange 0-0 lookup main proto 52",
	} {
		if !strings.Contains(rules6, want) {
			exitStep.Fatalf("[client] IPv6 ip rules lack %q", want)
		}
	}
	if got := ssh(client, "ip -4 rule show | grep -c 'proto 52' || true"); got != "0" {
		exitStep.Fatalf("[client] %s IPv4 underlay rules with loose rp_filter; want none", got)
	}
	clientDropsBefore := rpfDrops(client)
	wantV6Direct(exitStep, client)
	if got := rpfDrops(client); got != clientDropsBefore {
		exitStep.Fatalf("[client] rpfilter drops %d -> %d with the underlay rules in place; want none", clientDropsBefore, got)
	}

	// The control: no rules, and peer's pongs over IPv6 are dropped by the
	// filter, so no direct path.
	if got := ssh(control, "ip -6 rule show | grep -c 'proto 52' || true"); got != "0" {
		exitStep.Fatalf("[control] has %s underlay rules despite the kill switch", got)
	}
	controlDropsBefore := rpfDrops(control)
	ctlPing := ssh(control, fmt.Sprintf("tailscale ping -c 10 --timeout 3s %s 2>&1 || true", tailscaleIP(peer)))
	t.Logf("[control] tailscale ping peer:\n%s", ctlPing)
	if strings.Contains(ctlPing, "via [2000:3:") {
		exitStep.Fatalf("[control] got a direct IPv6 path to peer without the rules; topology doesn't reproduce the bug for IPv6")
	}
	if after := rpfDrops(control); after <= controlDropsBefore {
		exitStep.Fatalf("[control] rpfilter drops %d -> %d; want dropped replies", controlDropsBefore, after)
	} else {
		t.Logf("[control] rpfilter drops %d -> %d", controlDropsBefore, after)
	}
	exitStep.End(nil)

	cleanupStep.Begin()
	env.SetExitNode(client, nil)
	eventually(cleanupStep, client, "IPv6 underlay rules to be removed", "ip -6 rule show | grep -c 'proto 52' || true", func(out string) bool {
		return out == "0"
	})
	cleanupStep.End(nil)
}
