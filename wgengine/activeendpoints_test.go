// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestDebugActiveEndpoints(t *testing.T) {
	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	const nodeHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nk := nkFromHex(nodeHex)
	dk := key.NewDisco().Public()
	nm := &netmap.NetworkMap{
		Peers: nodeViews([]*tailcfg.Node{
			{
				ID:       1,
				Key:      nk,
				DiscoKey: dk,
			},
		}),
	}
	cfg := &wgcfg.Config{
		Peers: []wgcfg.Peer{
			{
				PublicKey: nk,
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32),
				},
			},
		},
	}
	e.SetNetworkMap(nm)
	// LocalBackend, not the engine, pushes the netmap's peers into
	// magicsock; do the same here so magicsock knows about the peer.
	ue := e.(*userspaceEngine)
	ue.magicConn.SetNetworkMap(tailcfg.NodeView{}, nm.Peers)
	if err := e.Reconfig(cfg, &router.Config{}, &dns.Config{}); err != nil {
		t.Fatal(err)
	}

	// Initially the peer should be known to magicsock, but wireguard-go
	// should not have created its (lazily-created) peer yet.
	res, err := e.DebugActiveEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Peers) != 1 {
		t.Fatalf("got %d peers; want 1", len(res.Peers))
	}
	p := res.Peers[0]
	if p.NodeKey != nk {
		t.Errorf("NodeKey = %v; want %v", p.NodeKey, nk)
	}
	if p.Magicsock == nil {
		t.Error("Magicsock state missing; want present")
	} else {
		if p.Magicsock.IsWireGuardOnly {
			t.Error("IsWireGuardOnly = true; want false for disco-capable peer")
		}
		if p.Magicsock.Expired {
			t.Error("Expired = true; want false")
		}
	}
	if want := dk.ShortString(); p.ShortDisco != want {
		t.Errorf("ShortDisco = %q; want %q", p.ShortDisco, want)
	}
	if p.WireGuard != nil {
		t.Errorf("WireGuard state = %+v; want nil (peer should not be created yet)", p.WireGuard)
	}

	// Force wireguard-go to create the peer, as it would upon first
	// packet exchanged with it, and verify the WireGuard state appears
	// with a magicsock-managed endpoint.
	if peer := ue.wgdev.LookupPeer(device.NoisePublicKey(nk.Raw32())); peer == nil {
		t.Fatal("LookupPeer failed to create peer")
	}
	res, err = e.DebugActiveEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Peers) != 1 {
		t.Fatalf("got %d peers; want 1", len(res.Peers))
	}
	p = res.Peers[0]
	if p.WireGuard == nil {
		t.Fatal("WireGuard state missing; want present after peer creation")
	}
	if p.WireGuard.Endpoint != nodeHex {
		t.Errorf("WireGuard.Endpoint = %q; want %q", p.WireGuard.Endpoint, nodeHex)
	}
	if p.WireGuard.EndpointType != ipnstate.WireGuardEndpointTypeMagicsock {
		t.Errorf("WireGuard.EndpointType = %q; want %q", p.WireGuard.EndpointType, ipnstate.WireGuardEndpointTypeMagicsock)
	}
	if !p.WireGuard.LastHandshake.IsZero() {
		t.Errorf("WireGuard.LastHandshake = %v; want zero", p.WireGuard.LastHandshake)
	}

	j, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DebugActiveEndpoints JSON:\n%s", j)
}
