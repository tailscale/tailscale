// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

	"tailscale.com/disco"
	"tailscale.com/types/key"
)

func TestRelayManagerInitAndIdle(t *testing.T) {
	rm := relayManager{}
	rm.allocateAndHandshakeAllServers(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.stopWork(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleCallMeMaybeVia(&endpoint{c: &Conn{discoPrivate: key.NewDisco()}}, &disco.CallMeMaybeVia{ServerDisco: key.NewDisco().Public()})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleGeneveEncapDiscoMsgNotBestAddr(&disco.BindUDPRelayEndpointChallenge{}, &discoInfo{}, netip.AddrPort{}, 0)
	<-rm.runLoopStoppedCh
}
