// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
)

// TestSelfSignedDERPHashPinning exercises the sha256-raw DERP cert pinning
// code path end-to-end: tailscaled connects to its home DERP whose cert is
// self-signed and pinned via CertName="sha256-raw:<hex>" (no separate
// fronting CertName), the two nodes communicate over the resulting tailnet,
// and `tailscale debug derp` against the same region succeeds.
//
// Both nodes sit behind hard NATs with no port mapping available so disco
// cannot punch a direct path and the tailnet ping must traverse DERP, making
// the sha256-raw pinning of the tailscaled→DERP path part of the assertion.
//
// The debug-derp half is the regression test for the bug fixed in PR #19965:
// before that change, [ipn/localapi.serveDebugDERPRegion] passed the raw
// sha256-raw fingerprint as the TLS ServerName and the handshake always
// failed with a hostname mismatch.
func TestSelfSignedDERPHashPinning(t *testing.T) {
	env := vmtest.New(t, vmtest.SelfSignedDERPCertPinning())
	n1 := hard(env)
	n2 := hard(env)
	env.Start()

	if err := env.PingExpect(n1, n2, vmtest.PingRouteDERP, 60*time.Second); err != nil {
		t.Fatalf("ping node-0 -> node-1: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	for _, n := range []*vmtest.Node{n1, n2} {
		rep, err := n.Agent().DebugDERPRegion(ctx, "1")
		if err != nil {
			t.Fatalf("[%s] DebugDERPRegion(1): %v", n.Name(), err)
		}
		t.Logf("[%s] DebugDERPRegion(1): info=%v warnings=%v errors=%v",
			n.Name(), rep.Info, rep.Warnings, rep.Errors)
		for _, e := range rep.Errors {
			// The `hard` builder gives the node only an IPv4 LAN, so the
			// DebugDERPRegion IPv6 probe predictably fails with
			// "network is unreachable". That's orthogonal to the TLS
			// verification path this test exists to cover.
			if strings.Contains(e, "over IPv6") {
				continue
			}
			t.Errorf("[%s] DebugDERPRegion(1) error: %s", n.Name(), e)
		}
	}
}
