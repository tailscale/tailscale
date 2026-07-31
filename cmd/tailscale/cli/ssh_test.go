// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// TestGenKnownHostsDNSNameInjection verifies that a peer whose DNSName
// contains newline characters (as could be supplied by a malicious
// coordination server via Node.Name) does not inject additional lines into
// the generated ssh_known_hosts file.
func TestGenKnownHostsDNSNameInjection(t *testing.T) {
	nk := key.NewNode().Public()
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nk: {
				DNSName:      "node.attacker.net\n* ssh-ed25519 AAAAattackerkey",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
				SSH_HostKeys: []string{"ssh-ed25519 AAAAlegitkey"},
			},
		},
	}

	got := string(genKnownHosts(st))

	if strings.Contains(got, "* ssh-ed25519 AAAAattackerkey") {
		t.Errorf("known_hosts output contains injected wildcard line:\n%s", got)
	}
}
