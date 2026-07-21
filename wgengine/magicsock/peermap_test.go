// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/key"
)

func Test_peerMap_oneRelayEpAddrPerNK(t *testing.T) {
	pm := newPeerMap()
	nk := key.NewNode().Public()
	ep := &endpoint{
		nodeID:    1,
		publicKey: nk,
	}
	ed := &endpointDisco{key: key.NewDisco().Public()}
	ep.disco.Store(ed)
	pm.upsertEndpoint(ep, key.DiscoPublic{})
	vni := packet.VirtualNetworkID{}
	vni.Set(1)
	relayEpAddrA := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:1"), vni: vni}
	relayEpAddrB := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:2"), vni: vni}
	pm.setNodeKeyForEpAddr(relayEpAddrA, nk)
	pm.setNodeKeyForEpAddr(relayEpAddrB, nk)
	if len(pm.byEpAddr) != 1 {
		t.Fatalf("expected 1 epAddr in byEpAddr, got: %d", len(pm.byEpAddr))
	}
	got := pm.relayEpAddrByNodeKey[nk]
	if got != relayEpAddrB {
		t.Fatalf("expected relay epAddr %v, got: %v", relayEpAddrB, got)
	}
}

func Test_peerMap_nodesOfDisco_upsertCleansOldKey(t *testing.T) {
	pm := newPeerMap()
	nk := key.NewNode().Public()
	discoK1 := key.NewDisco().Public()
	discoK2 := key.NewDisco().Public()

	ep := &endpoint{nodeID: 1, publicKey: nk}
	ep.disco.Store(&endpointDisco{key: discoK1})
	pm.upsertEndpoint(ep, key.DiscoPublic{}) // insert with K1

	if !pm.knownPeerDiscoKey(discoK1) {
		t.Fatal("expected K1 to be known after initial upsert")
	}

	// Rotate disco
	ep.disco.Store(&endpointDisco{key: discoK2})
	pm.upsertEndpoint(ep, discoK1)

	if pm.knownPeerDiscoKey(discoK1) {
		t.Error("old disco key K1 is still known after rotation")
	}
	if old, ok := pm.nodesOfDisco[discoK1]; ok {
		t.Errorf("old disco key K1 should be absent from nodesOfDisco, but entry %v remains", old)
	}
	if !pm.knownPeerDiscoKey(discoK2) {
		t.Error("new disco key K2 should be known after rotation")
	}
}

func Test_peerMap_nodesOfDisco_deleteCleansKey(t *testing.T) {
	pm := newPeerMap()
	nk := key.NewNode().Public()
	dk := key.NewDisco().Public()

	conn := newTestConn(t)
	ep := &endpoint{
		nodeID:        1,
		publicKey:     nk,
		c:             conn,
		endpointState: map[netip.AddrPort]*endpointState{},
	}
	ep.disco.Store(&endpointDisco{key: dk})
	pm.upsertEndpoint(ep, key.DiscoPublic{})

	if !pm.knownPeerDiscoKey(dk) {
		t.Fatal("expected disco key to be known after upsert")
	}

	pm.deleteEndpoint(ep)

	if pm.knownPeerDiscoKey(dk) {
		t.Error("disco key is still known after deletion")
	}
	if s, ok := pm.nodesOfDisco[dk]; ok {
		t.Errorf("nodesOfDisco for deleted key: found %v, want absent", s)
	}
}

func Test_peerMap_nodesOfDisco_sharedDiscoKey(t *testing.T) {
	pm := newPeerMap()
	nk1 := key.NewNode().Public()
	nk2 := key.NewNode().Public()
	dk := key.NewDisco().Public()

	conn := newTestConn(t)

	ep1 := &endpoint{
		nodeID:        1,
		publicKey:     nk1,
		c:             conn,
		endpointState: map[netip.AddrPort]*endpointState{},
	}
	ep1.disco.Store(&endpointDisco{key: dk})
	pm.upsertEndpoint(ep1, key.DiscoPublic{})

	ep2 := &endpoint{
		nodeID:        2,
		publicKey:     nk2,
		c:             conn,
		endpointState: map[netip.AddrPort]*endpointState{},
	}
	ep2.disco.Store(&endpointDisco{key: dk})
	pm.upsertEndpoint(ep2, key.DiscoPublic{})

	pm.deleteEndpoint(ep1)

	if !pm.knownPeerDiscoKey(dk) {
		t.Error("shared disco key should still be known after one of two peers is removed")
	}

	pm.deleteEndpoint(ep2)

	if pm.knownPeerDiscoKey(dk) {
		t.Error("disco key should be unknown after both peers removed")
	}
}
