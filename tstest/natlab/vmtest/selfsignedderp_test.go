// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// easyAnd6NoEndpoints is easy NAT plus an IPv6 prefix and
// TS_DEBUG_STRIP_ENDPOINTS=1 on tailscaled so peer endpoints from control
// are dropped. That forces the initial peer-to-peer disco bootstrap to
// traverse DERP, since without endpoints from control the nodes have no
// other way to first learn about each other.
func easyAnd6NoEndpoints(env *vmtest.Env) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(fmt.Sprintf("node-%d", n),
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n),
			v6cidr(n),
			vnet.EasyNAT),
		vnet.TailscaledEnv{Key: "TS_DEBUG_STRIP_ENDPOINTS", Value: "1"},
		vmtest.OS(vmtest.Gokrazy))
}

// TestSelfSignedDERPHashPinning exercises the sha256-raw DERP cert pinning
// code path end-to-end: tailscaled connects to its home DERP whose cert is
// self-signed and pinned via CertName="sha256-raw:<hex>" (no separate
// fronting CertName), the two nodes communicate over the resulting tailnet,
// and `tailscale debug derp` against the same region succeeds.
//
// Nodes are dual-stack (v4 + v6) so the DebugDERPRegion probe exercises both
// address families against the test DERP server. They additionally strip
// peer endpoints from control so the initial peer-to-peer disco bootstrap
// must traverse DERP; the eventual data path may be direct or DERP, the
// test doesn't care, only that DERP worked end-to-end.
//
// The debug-derp half is the regression test for the bug fixed in PR #19965:
// before that change, [ipn/localapi.serveDebugDERPRegion] passed the raw
// sha256-raw fingerprint as the TLS ServerName and the handshake always
// failed with a hostname mismatch.
func TestSelfSignedDERPHashPinning(t *testing.T) {
	env := vmtest.New(t, vmtest.SelfSignedDERPCertPinning())
	n1 := easyAnd6NoEndpoints(env)
	n2 := easyAnd6NoEndpoints(env)
	env.Start()

	// End-to-end ping over the WireGuard tunnel. With peer endpoints
	// stripped from control, the only way for the peers to first reach each
	// other is via DERP, so a successful tunnel ping proves the
	// tailscaled→DERP TLS handshake (and thus sha256-raw cert pinning)
	// worked on both ends.
	if err := env.Ping(n1, n2, tailcfg.PingTSMP, 60*time.Second); err != nil {
		t.Fatalf("ping node-0 -> node-1: %v", err)
	}

	// Also verify each node both sent and received data packets over DERP.
	// With endpoints stripped from control, the TSMP ping above has no
	// direct path available, so the WireGuard packets it generates must
	// flow via DERP. These counters never decrease, so once they're
	// non-zero we know DERP carried real frames in both directions.
	for _, n := range []*vmtest.Node{n1, n2} {
		if err := tstest.WaitFor(30*time.Second, func() error {
			m := env.ClientMetrics(n)
			sent := m["magicsock_send_data_derp"].Value
			recv := m["magicsock_recv_data_derp"].Value
			if sent == 0 || recv == 0 {
				return fmt.Errorf("DERP data packets: sent=%d recv=%d; want both > 0", sent, recv)
			}
			t.Logf("[%s] DERP data packets: sent=%d recv=%d", n.Name(), sent, recv)
			return nil
		}); err != nil {
			t.Errorf("[%s] %v", n.Name(), err)
		}
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
