// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
)

// TestJailedAndMasqueradedPeers exercises the tun-layer per-peer data
// plane end-to-end with two gokrazy VMs: the control server marks one
// peer jailed (so the other side's jailed packet filter must drop its
// TCP flows) and later assigns masquerade addresses (so per-packet
// NAT must rewrite addresses in both directions). Connectivity is
// probed with HTTP requests between the nodes' webservers, which flow
// through the WireGuard tunnel and the tun-layer filters; TSMP pings
// are no good here because tstun answers them before running the
// packet filter. Each transition arrives as a netmap update and must
// take effect without restarting anything.
func TestJailedAndMasqueradedPeers(t *testing.T) {
	env := vmtest.New(t, vmtest.AllOnline())
	addNode := func() *vmtest.Node {
		n := env.NumNodes()
		return env.AddNode(fmt.Sprintf("node-%d", n),
			env.AddNetwork(
				fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
				fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
			vmtest.OS(vmtest.Gokrazy),
			vmtest.WebServer(8080))
	}
	n1 := addNode()
	n2 := addNode()
	env.Start()

	st1 := env.Status(n1)
	st2 := env.Status(n2)
	k1, k2 := st1.Self.PublicKey, st2.Self.PublicKey
	n1IP, n2IP := st1.Self.TailscaleIPs[0], st2.Self.TailscaleIPs[0]
	cs := env.ControlServer()

	url := func(ip netip.Addr) string { return fmt.Sprintf("http://%s:8080/", ip) }

	// awaitHTTPOK polls until an HTTP GET from the given node succeeds
	// and the body carries the serving node's greeting, proving the
	// TCP flow crossed the tunnel to the intended node.
	awaitHTTPOK := func(from *vmtest.Node, targetURL, wantGreeting string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		var lastErr error
		for time.Now().Before(deadline) {
			res, err := env.HTTPGetStatus(from, targetURL)
			if err == nil && res.Status == 200 && strings.Contains(res.Body, wantGreeting) {
				return
			}
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("status=%d body=%q", res.Status, res.Body)
			}
		}
		t.Fatalf("GET %s from %s never succeeded: %v", targetURL, from.Name(), lastErr)
	}

	// awaitHTTPFails polls until an HTTP GET from the given node
	// fails, for asserting that a jailed peer's flows get dropped
	// once the netmap update lands.
	awaitHTTPFails := func(from *vmtest.Node, targetURL string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			res, err := env.HTTPGetStatus(from, targetURL)
			if err != nil || res.Status != 200 {
				return
			}
		}
		t.Fatalf("GET %s from %s still succeeding; want drop by jailed filter", targetURL, from.Name())
	}

	// Warm up the tunnel, then check HTTP in both directions.
	if err := env.Ping(n1, n2, tailcfg.PingTSMP, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	awaitHTTPOK(n2, url(n1IP), n1.Name())
	awaitHTTPOK(n1, url(n2IP), n2.Name())

	// Jail n2 as seen by n1: n1's data plane must start dropping
	// n2-initiated flows.
	cs.SetJailed(k1, k2, true)
	awaitHTTPFails(n2, url(n1IP))

	// Unjailing must restore connectivity the same way.
	cs.SetJailed(k1, k2, false)
	awaitHTTPOK(n2, url(n1IP), n1.Name())
	awaitHTTPOK(n1, url(n2IP), n2.Name())

	// Masquerade both nodes: each side now knows the other only by
	// its masquerade address, and the tun layer must NAT between the
	// masquerade and native addresses in both directions.
	n1Masq := netip.MustParseAddr("100.64.101.1")
	n2Masq := netip.MustParseAddr("100.64.102.1")
	cs.SetMasqueradeAddresses([]testcontrol.MasqueradePair{
		{Node: k1, Peer: k2, NodeMasqueradesAs: n1Masq},
		{Node: k2, Peer: k1, NodeMasqueradesAs: n2Masq},
	})

	// Wait for each side's netmap to show the peer at its masquerade
	// address, then fetch through it.
	awaitPeerIP := func(on *vmtest.Node, peer key.NodePublic, want netip.Addr) {
		t.Helper()
		deadline := time.Now().Add(time.Minute)
		for time.Now().Before(deadline) {
			if ps, ok := env.Status(on).Peer[peer]; ok {
				for _, ip := range ps.TailscaleIPs {
					if ip == want {
						return
					}
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s never saw peer %s at %v", on.Name(), peer.ShortString(), want)
	}
	awaitPeerIP(n1, k2, n2Masq)
	awaitPeerIP(n2, k1, n1Masq)

	awaitHTTPOK(n2, url(n1Masq), n1.Name())
	awaitHTTPOK(n1, url(n2Masq), n2.Name())
}
