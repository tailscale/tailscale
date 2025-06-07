// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

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
	vni := virtualNetworkID{}
	vni.set(1)
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
