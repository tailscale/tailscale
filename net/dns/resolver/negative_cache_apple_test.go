// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package resolver

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

// TestTrackNegativeAnswers checks that only authoritative NXDOMAIN answers
// enter the tracker, with case-normalized names and reverse queries included.
func TestTrackNegativeAnswers(t *testing.T) {
	for _, tt := range []struct {
		name dnsname.FQDN
		typ  dns.Type
		want dnsname.FQDN
	}{
		{"TEST3.IPN.DEV.", dns.TypeA, "test3.ipn.dev."},
		{"test3.ipn.dev.", dns.TypeAAAA, "test3.ipn.dev."},
		{"test3.ipn.dev.", dns.TypeMX, "test3.ipn.dev."},
		{"test1.ipn.dev.", dns.TypeA, ""},
		{"test1.ipn.dev.", dns.TypeAAAA, ""},
		{"9.3.2.1.in-addr.arpa.", dns.TypePTR, "9.3.2.1.in-addr.arpa."},
		{"foo.onion.", dns.TypeA, ""},
		{"outside.example.", dns.TypeA, ""},
	} {
		t.Run(string(tt.name)+tt.typ.String(), func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			if err := r.SetConfig(dnsCfg); err != nil {
				t.Fatal(err)
			}
			_, err := r.respond(dnspacket(tt.name, tt.typ, noEdns))
			if err != nil && err != errNotOurName {
				t.Fatal(err)
			}
			if tt.want == "" {
				if r.negativeCache.entries.Len() != 0 {
					t.Fatal("non-authoritative-NXDOMAIN was tracked")
				}
			} else if _, ok := r.negativeCache.entries.PeekOk(tt.want); !ok {
				t.Fatalf("missing negative %s", tt.want)
			}
		})
	}
}

// negativeCacheUpdatingHosts runs an update after a lookup has observed a miss,
// but before the resolver can record the resulting NXDOMAIN.
type negativeCacheUpdatingHosts struct {
	fakeMagicDNSHosts
	afterMiss func()
}

func (h *negativeCacheUpdatingHosts) missed() {
	if f := h.afterMiss; f != nil {
		h.afterMiss = nil
		f()
	}
}

func (h *negativeCacheUpdatingHosts) LookupHost(name dnsname.FQDN) ([]netip.Addr, bool) {
	ips, ok := h.fakeMagicDNSHosts.LookupHost(name)
	if !ok {
		h.missed()
	}
	return ips, ok
}

func (h *negativeCacheUpdatingHosts) LookupPTR(ip netip.Addr) (dnsname.FQDN, bool) {
	name, ok := h.fakeMagicDNSHosts.LookupPTR(ip)
	if !ok {
		h.missed()
	}
	return name, ok
}

// TestNegativeCacheUpdateDuringQuery covers a query that observes a missing peer
// just before a peer update checks the still-empty negative-answer history.
// Returning NXDOMAIN for the newly available peer would leave the OS's stale
// negative cached until expiry or another update. The afterMiss callback forces
// this ordering without timing or goroutines.
//
// A, AAAA, and PTR queries must retry and answer from the new peer; a cache reset
// during resolution must likewise invalidate the pending negative. An unrelated
// update must leave a retried NXDOMAIN tracked for a later matching update, while
// a discarded negative must not cause a subsequent cache flush.
func TestNegativeCacheUpdateDuringQuery(t *testing.T) {
	for _, tt := range []struct {
		name         string
		typ          dns.Type
		stillMissing bool
		reset        bool
	}{
		{name: "A", typ: dns.TypeA},
		{name: "AAAA", typ: dns.TypeAAAA},
		{name: "PTR", typ: dns.TypePTR},
		{name: "unrelated update", typ: dns.TypeA, stillMissing: true},
		{name: "reset", typ: dns.TypeA, reset: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			if err := r.SetConfig(Config{LocalDomains: []dnsname.FQDN{"test.net.", "64.100.in-addr.arpa."}}); err != nil {
				t.Fatal(err)
			}
			hosts := &negativeCacheUpdatingHosts{}
			r.SetMagicDNSHosts(hosts)
			const name dnsname.FQDN = "server.test.net."
			ip4 := netip.MustParseAddr("100.64.0.2")
			ip6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
			addPeer := func() {
				hosts.hosts = map[dnsname.FQDN][]netip.Addr{name: {ip4, ip6}}
				hosts.ptr = map[netip.Addr]dnsname.FQDN{ip4: name}
			}
			hosts.afterMiss = func() {
				if !tt.stillMissing {
					addPeer()
				}
				if tt.reset {
					r.ClearNegativeCache()
				} else if r.CheckCachedDNS() {
					t.Fatal("empty history requested a flush")
				}
			}
			queryName := name
			if tt.typ == dns.TypePTR {
				queryName = "2.0.64.100.in-addr.arpa."
			}
			packet, err := r.respond(dnspacket(queryName, tt.typ, noEdns))
			if err != nil {
				t.Fatal(err)
			}
			var msg dns.Message
			if err := msg.Unpack(packet); err != nil {
				t.Fatal(err)
			}
			want := dns.RCodeSuccess
			if tt.stillMissing {
				want = dns.RCodeNameError
			}
			if msg.RCode != want {
				t.Fatalf("rcode = %v, want %v", msg.RCode, want)
			}
			if tt.stillMissing {
				// A retried query that is still negative must remain tracked
				// so a subsequent matching peer update can flush it.
				addPeer()
				if !r.CheckCachedDNS() {
					t.Fatal("retried NXDOMAIN was not tracked")
				}
			} else if len(msg.Answers) != 1 {
				t.Fatalf("answers = %v, want one answer from the new peer", msg.Answers)
			}
			if r.CheckCachedDNS() {
				t.Fatal("unsent NXDOMAIN requested a flush")
			}
		})
	}
}

// TestCheckCachedDNS checks name matching, expiry, subdomain capabilities,
// and history clearing when deciding whether a cached NXDOMAIN needs a flush.
func TestCheckCachedDNS(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		query                   dnsname.FQDN
		subdomains, reset, want bool
		age                     time.Duration
	}{
		{name: "exact", query: "server.test.net.", want: true},
		{name: "unqueried"},
		{name: "unrelated", query: "other.test.net."},
		{name: "recent", query: "server.test.net.", age: negativeCacheLifetime - time.Nanosecond, want: true},
		{name: "expired", query: "server.test.net.", age: negativeCacheLifetime},
		{name: "subdomain", query: "foo.server.test.net.", subdomains: true, want: true},
		{name: "nested subdomain", query: "foo.bar.server.test.net.", subdomains: true, want: true},
		{name: "no subdomain capability", query: "foo.server.test.net."},
		{name: "label boundary", query: "foo.otherserver.test.net.", subdomains: true},
		{name: "profile reset", query: "server.test.net.", reset: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			now := time.Unix(1000, 0)
			r.negativeCache.now = func() time.Time { return now }
			cfg := Config{LocalDomains: []dnsname.FQDN{"test.net."}}
			if err := r.SetConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if tt.query != "" {
				if _, err := r.respond(dnspacket(tt.query, dns.TypeA, noEdns)); err != nil {
					t.Fatal(err)
				}
			}
			if r.CheckCachedDNS() {
				t.Fatal("still missing name triggered flush")
			}
			now = now.Add(tt.age)
			if tt.reset {
				r.ClearNegativeCache()
			}
			cfg.Hosts = map[dnsname.FQDN][]netip.Addr{"server.test.net.": {netip.MustParseAddr("100.64.0.1")}}
			if tt.subdomains {
				cfg.SubdomainHosts = set.Of[dnsname.FQDN]("server.test.net.")
			}
			if err := r.SetConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if got := r.CheckCachedDNS(); got != tt.want {
				t.Fatalf("flush = %v, want %v", got, tt.want)
			}
			if r.CheckCachedDNS() {
				t.Fatal("repeated update requested another flush")
			}
		})
	}
}

// TestNegativeCacheBoundedAndConcurrent checks the LRU capacity under serial
// and concurrent inserts, and verifies recording resumes after clearing.
func TestNegativeCacheBoundedAndConcurrent(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		workers, perWorker, want int
	}{
		{"below capacity", 1, 10, 10},
		{"at capacity", 1, maxRecentNXDomains, maxRecentNXDomains},
		{"concurrent overflow", 100, 50, maxRecentNXDomains},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			var wg sync.WaitGroup
			for i := range tt.workers {
				wg.Go(func() {
					for j := range tt.perWorker {
						r.negativeCache.record(dnsname.FQDN(fmt.Sprintf("peer%d-%d.test.net.", i, j)), r.negativeCache.queryGeneration())
					}
				})
			}
			wg.Wait()
			if got := r.negativeCache.entries.Len(); got != tt.want {
				t.Fatalf("entries = %d, want %d", got, tt.want)
			}
			r.ClearNegativeCache()
			if r.negativeCache.entries.Len() != 0 {
				t.Fatal("global flush did not clear the LRU")
			}
			r.negativeCache.record("fresh.test.net.", r.negativeCache.queryGeneration())
			if r.negativeCache.entries.Len() != 1 {
				t.Fatal("negative after flush was lost")
			}
		})
	}
}

// TestNegativeCacheRepeatedAnswerRefreshesAge checks that repeated negative
// answers restart the tracking lifetime and eventually expire.
func TestNegativeCacheRepeatedAnswerRefreshesAge(t *testing.T) {
	for _, tt := range []struct {
		name    string
		repeat  bool
		elapsed time.Duration
		want    bool
	}{
		{"without refresh", false, 2 * time.Second, false},
		{"refreshed", true, 2 * time.Second, true},
		{"refresh expired", true, negativeCacheLifetime, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			now := time.Unix(1000, 0)
			r.negativeCache.now = func() time.Time { return now }
			r.negativeCache.record("server.test.net.", r.negativeCache.queryGeneration())
			now = now.Add(negativeCacheLifetime - time.Second)
			if tt.repeat {
				r.negativeCache.record("server.test.net.", r.negativeCache.queryGeneration())
			}
			now = now.Add(tt.elapsed)
			if err := r.SetConfig(Config{Hosts: map[dnsname.FQDN][]netip.Addr{"server.test.net.": {netip.MustParseAddr("100.64.0.1")}}}); err != nil {
				t.Fatal(err)
			}
			if got := r.CheckCachedDNS(); got != tt.want {
				t.Fatalf("flush = %v, want %v", got, tt.want)
			}
		})
	}
}
