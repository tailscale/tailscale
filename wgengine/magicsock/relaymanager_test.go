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
}
