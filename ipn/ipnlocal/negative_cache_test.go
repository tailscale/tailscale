// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"net/netip"
	"runtime"
	"testing"

	dnsmsg "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// TestNegativeCachePeerUpdates checks that matching peer arrivals and subdomain
// capability changes flush recent NXDOMAINs only on Apple builds.
func TestNegativeCachePeerUpdates(t *testing.T) {
	for _, goos := range []string{"darwin", "ios", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			for _, tt := range []struct {
				name, query                     string
				unrelated, existing, subdomains bool
				want                            int
			}{
				{name: "peer arrival", query: "server.test.net.", want: 1},
				{name: "unqueried peer arrival"},
				{name: "unrelated then matching peer", query: "server.test.net.", unrelated: true, want: 1},
				{name: "subdomain without capability", query: "foo.server.test.net.", existing: true},
				{name: "subdomain capability added", query: "foo.server.test.net.", existing: true, subdomains: true, want: 1},
			} {
				t.Run(tt.name, func(t *testing.T) {
					bus := eventbustest.NewBus(t)
					sys := tsd.NewSystemWithBus(bus)
					dialer := tsdial.NewDialer(netmon.NewStatic())
					dialer.SetBus(bus)
					oscfg, err := dns.NewNoopManager()
					if err != nil {
						t.Fatal(err)
					}
					dm := dns.NewManager(t.Logf, oscfg, health.NewTracker(bus), dialer, nil, nil, goos, bus)
					defer dm.Down()
					sys.DNSManager.Set(dm)
					b := &LocalBackend{ctx: context.Background(), logf: t.Logf, sys: sys, extHost: &ExtensionHost{}}
					cn := b.currentNode()
					defer cn.shutdown(nil)
					dm.Resolver().SetMagicDNSHosts(magicDNSHosts{b})
					if err := dm.Resolver().SetConfig(resolver.Config{LocalDomains: []dnsname.FQDN{"test.net."}}); err != nil {
						t.Fatal(err)
					}
					flushed := 0
					dm.SetCacheFlushHook(func() { flushed++ })
					self := (&tailcfg.Node{ID: 1, Name: "self.test.net.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}).View()
					cn.SetNetMap(&netmap.NetworkMap{SelfNode: self, DNS: tailcfg.DNSConfig{Proxied: true}})
					negative := func(name string) {
						t.Helper()
						packet, err := (&dnsmsg.Message{Questions: []dnsmsg.Question{{Name: dnsmsg.MustNewName(name), Type: dnsmsg.TypeA, Class: dnsmsg.ClassINET}}}).Pack()
						if err != nil {
							t.Fatal(err)
						}
						out, err := dm.Query(context.Background(), packet, "udp", netip.MustParseAddrPort("100.64.0.1:12345"))
						if err != nil {
							t.Fatal(err)
						}
						var response dnsmsg.Message
						if err := response.Unpack(out); err != nil {
							t.Fatal(err)
						}
						if response.RCode != dnsmsg.RCodeNameError {
							t.Fatalf("rcode=%v for %s", response.RCode, name)
						}
					}
					update := func(peer *tailcfg.Node) {
						t.Helper()
						cn.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: peer.View()}})
						b.mu.Lock()
						b.checkCachedDNSLocked()
						b.mu.Unlock()
					}
					peer := &tailcfg.Node{ID: 2, Name: "server.test.net.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
					if tt.existing {
						update(peer)
					}
					if tt.query != "" {
						negative(tt.query)
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
					for check := range 2 {
						update(peer)
						if flushed != want {
							t.Fatalf("update %d: flushes = %d, want %d", check, flushed, want)
						}
					}
				})
			}
		})
	}
}
