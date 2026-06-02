// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// hardDualNoEndpoints is hard NAT with both an IPv4 LAN and an IPv6 prefix
// (so the DebugDERPRegion probe exercises both address families against the
// test DERP server) and TS_DEBUG_STRIP_ENDPOINTS=1 set on tailscaled so it
// doesn't announce any direct endpoints to peers. Combined on both nodes,
// that leaves DERP as the only available path for the tailnet ping. The
// home DERP itself is left alone so the sha256-raw verification path is
// still exercised.
func hardDualNoEndpoints(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("10.0.%d.1/24", n),
			v6cidr(n),
			vnet.HardNAT),
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_ENDPOINTS", Value: "1"},
		vmtest.OS(vmtest.Gokrazy))
}

// TestSelfSignedDERPHashPinning exercises the sha256-raw DERP cert pinning
// code path end-to-end: tailscaled connects to its home DERP whose cert is
// self-signed and pinned via CertName="sha256-raw:<hex>" (no separate
// fronting CertName), the two nodes communicate over the resulting tailnet,
// and `tailscale debug derp` against the same region succeeds.
//
// Both nodes sit behind hard NATs and additionally strip their direct
// endpoints (TS_DEBUG_STRIP_ENDPOINTS=1) so disco cannot find a direct path
// and the tailnet ping must traverse DERP, making the sha256-raw pinning of
// the tailscaled→DERP path part of the assertion. (Stripping endpoints — not
// just relying on hard NAT — is needed because the dual-stack LAN provides a
// non-NATted IPv6 path that the nodes would otherwise discover.)
//
// The debug-derp half is the regression test for the bug fixed in PR #19965:
// before that change, [ipn/localapi.serveDebugDERPRegion] passed the raw
// sha256-raw fingerprint as the TLS ServerName and the handshake always
// failed with a hostname mismatch.
func TestSelfSignedDERPHashPinning(t *testing.T) {
	env := vmtest.New(t, vmtest.SelfSignedDERPCertPinning())
	n1 := hardDualNoEndpoints(env)
	n2 := hardDualNoEndpoints(env)
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
		if len(rep.Errors) > 0 {
			t.Errorf("[%s] DebugDERPRegion(1) reported errors: %s",
				n.Name(), strings.Join(rep.Errors, "; "))
		}
	}
}
