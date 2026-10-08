// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/internal/dnstest"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// TestNegativeCachePeerUpdates checks that matching peer arrivals and subdomain
// capability changes flush recent NXDOMAINs only on Apple builds.
func TestNegativeCachePeerUpdates(t *testing.T) {
	// Each case optionally issues a query that returns NXDOMAIN, then adds or
	// updates server.test.net through LocalBackend's delta path.
	for _, tt := range []struct {
		name       string
		query      string
		unrelated  bool // insert a different peer first to verify that only a matching update flushes
		existing   bool // insert the peer before the query to verify that only a later update flushes
		subdomains bool // grant subdomain resolution on the later update to verify that only a matching update flushes
		want       int  // expected number of flushes on this platform
	}{
		{name: "peer_arrival", query: "server.test.net.", want: 1},
		{name: "unqueried_peer_arrival"},
		{name: "unrelated_then_matching_peer", query: "server.test.net.", unrelated: true, want: 1},
		{name: "subdomain_without_capability", query: "foo.server.test.net.", existing: true},
		{name: "subdomain_capability_added", query: "foo.server.test.net.", existing: true, subdomains: true, want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			dm := b.sys.DNSManager.Get()
			cn := b.currentNode()
			if err := dm.Resolver().SetConfig(resolver.Config{LocalDomains: []dnsname.FQDN{"test.net."}}); err != nil {
				t.Fatal(err)
			}
			flushed := 0
			dm.SetCacheFlushHook(func() { flushed++ })
			self := (&tailcfg.Node{ID: 1, Name: "self.test.net.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}).View()
			cn.SetNetMap(&netmap.NetworkMap{SelfNode: self, DNS: tailcfg.DNSConfig{Proxied: true}})
			// Simulate receipt of a netmap delta to upsert peer.
			update := func(peer *tailcfg.Node) {
				t.Helper()
				if !b.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: peer.View()}}) {
					t.Fatal("UpdateNetmapDelta returned false")
				}
			}
			peer := &tailcfg.Node{ID: 2, Name: "server.test.net.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
			if tt.existing {
				update(peer)
			}
			if tt.query != "" {
				dnstest.RequireNXDOMAIN(t, dm.Query, tt.query)
			}
			if tt.unrelated {
				unrelated := &tailcfg.Node{ID: 3, Name: "other.test.net.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}}
				update(unrelated)
				if flushed != 0 {
					t.Fatal("unrelated peer arrival flushed a cached NXDOMAIN")
				}
			}
			if tt.subdomains {
				peer.CapMap = tailcfg.NodeCapMap{nodecap.DNSSubdomainResolve: nil}
			}
			want := tt.want
			if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
				// The compiled stub never requests a flush after a peer update.
				want = 0
			}
			// Repeat the update to verify the first flush cleared the history
			// and the same cached negative cannot trigger a second flush.
			for check := range 2 {
				update(peer)
				if flushed != want {
					t.Fatalf("update %d: flushes = %d, want %d", check, flushed, want)
				}
			}
		})
	}
}
