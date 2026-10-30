// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestFreeBSDRouteErrorKeepsTunnelRoutes checks that a FreeBSD node keeps its
// tunnel addresses and routes after router errors.
//
// The router used to record the tunnel's addresses only when a whole
// configuration succeeded, so any route error left that record stale. Two
// ways that bit:
//
//   - A node that comes up accepting a subnet route that collides with one of
//     its own (here its connected LAN) fails that route add with "File
//     exists". Its next reconfig then re-added the tunnel's IPv4 address,
//     and FreeBSD replaces an existing address by deleting it first, which
//     flushes every route through tailscale0.
//   - "tailscale down" removes the addresses, which drops their routes, so
//     the router's own route deletes fail. "tailscale up" then believed the
//     addresses were still there and left tailscale0 with none.
func TestFreeBSDRouteErrorKeepsTunnelRoutes(t *testing.T) {
	env := vmtest.New(t)

	wan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	lan := env.AddNetwork("10.0.0.1/24")

	// The FreeBSD node joins by hand below, once the colliding route exists,
	// so that its first router configuration hits the collision.
	bsd := env.AddNode("freebsd", wan, lan,
		vmtest.OS(vmtest.FreeBSD150),
		vmtest.DontJoinTailnet(),
		vnet.TailscaledEnv{Key: "TS_DEBUG_NETSTACK_SUBNETS", Value: "false"})
	peer := env.AddNode("peer", wan,
		vmtest.OS(vmtest.Gokrazy))

	env.Start()

	peerKey := env.Status(peer).Self.PublicKey
	peerIP := env.Status(peer).Self.TailscaleIPs[0]
	setRoutes := func(routes ...string) {
		var ps []netip.Prefix
		for _, r := range routes {
			ps = append(ps, netip.MustParsePrefix(r))
		}
		env.ControlServer().SetSubnetRoutes(peerKey, ps)
	}
	ssh := func(cmd string) string {
		t.Helper()
		out, err := env.SSHExec(bsd, cmd)
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return out
	}
	up := func() {
		t.Helper()
		if out, err := env.Tailscale(bsd, "up", "--login-server=http://control.tailscale", "--accept-routes"); err != nil {
			t.Fatalf("tailscale up: %v\n%s", err, out)
		}
	}
	waitFor := func(what string, ok func(string) bool, cmd string) {
		t.Helper()
		if err := tstest.WaitFor(30*time.Second, func() error {
			if out := ssh(cmd); !ok(out) {
				return fmt.Errorf("waiting for %s:\n%s", what, out)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	hasRoute := func(prefix string) func(string) bool {
		return func(out string) bool {
			for line := range strings.Lines(out) {
				if f := strings.Fields(line); len(f) >= 4 && f[0] == prefix && f[3] == "tailscale0" {
					return true
				}
			}
			return false
		}
	}
	check := func(when string) {
		t.Helper()
		out, err := env.Tailscale(bsd, "ip", "-4")
		if err != nil {
			t.Fatalf("tailscale ip -4: %v\n%s", err, out)
		}
		ip4 := strings.TrimSpace(out)
		if ifc := ssh("ifconfig tailscale0"); !strings.Contains(ifc, "inet "+ip4+" ") {
			t.Errorf("%s: tailscale0 lacks %v:\n%s", when, ip4, ifc)
		}
		if out := ssh("route -n get -inet " + peerIP.String()); !strings.Contains(out, "interface: tailscale0") {
			t.Errorf("%s: route to peer %v not via tailscale0:\n%s\nrouting table:\n%s",
				when, peerIP, out, ssh("netstat -rn -f inet"))
		}
	}

	setRoutes("10.0.0.0/24")
	up()
	const collision = "route -q -n add -inet 10.0.0.0/24 -iface tailscale0"
	waitFor("the colliding route add to fail",
		func(s string) bool { return strings.Contains(s, collision) }, "cat /var/log/tailscaled.log")

	// Any reconfig used to flush the tunnel routes; a new subnet route is a
	// convenient one, and waiting for it proves the router applied it.
	setRoutes("10.0.0.0/24", "10.9.0.0/24")
	waitFor("10.9.0.0/24 via tailscale0", hasRoute("10.9.0.0/24"), "netstat -rn -f inet")
	check("after reconfig")

	if out, err := env.Tailscale(bsd, "down"); err != nil {
		t.Fatalf("tailscale down: %v\n%s", err, out)
	}
	up()
	waitFor("10.9.0.0/24 via tailscale0", hasRoute("10.9.0.0/24"), "netstat -rn -f inet")
	check("after down and up")
}
