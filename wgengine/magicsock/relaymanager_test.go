// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

	"tailscale.com/disco"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

func TestRelayManagerInitAndIdle(t *testing.T) {
	rm := relayManager{}
	rm.startUDPRelayPathDiscoveryFor(&endpoint{}, addrQuality{}, false)
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.stopWork(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleCallMeMaybeVia(&endpoint{c: &Conn{discoPrivate: key.NewDisco()}}, addrQuality{}, false, &disco.CallMeMaybeVia{ServerDisco: key.NewDisco().Public()})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleGeneveEncapDiscoMsg(&Conn{discoPrivate: key.NewDisco()}, &disco.BindUDPRelayEndpointChallenge{}, &discoInfo{}, epAddr{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleRelayServersSet(make(set.Set[netip.AddrPort]))
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.getServers()
	<-rm.runLoopStoppedCh
}

func TestRelayManagerGetServers(t *testing.T) {
	rm := relayManager{}
	servers := make(set.Set[netip.AddrPort], 1)
	servers.Add(netip.MustParseAddrPort("192.0.2.1:7"))
	rm.handleRelayServersSet(servers)
	got := rm.getServers()
	if !servers.Equal(got) {
		t.Errorf("got %v != want %v", got, servers)
	}
}
