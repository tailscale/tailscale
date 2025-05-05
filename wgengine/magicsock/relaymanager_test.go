// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

	"tailscale.com/disco"
)

func TestRelayManagerInitAndIdle(t *testing.T) {
	rm := relayManager{}
	rm.allocateAndHandshakeAllServers(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.cancelOutstandingWork(&endpoint{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleCallMeMaybeVia(&disco.CallMeMaybeVia{})
	<-rm.runLoopStoppedCh

	rm = relayManager{}
	rm.handleBindUDPRelayEndpointChallenge(&disco.BindUDPRelayEndpointChallenge{}, &discoInfo{}, netip.AddrPort{}, 0)
	<-rm.runLoopStoppedCh
}
