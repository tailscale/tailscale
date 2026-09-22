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

func TestCheckCachedDNS(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		query                   dnsname.FQDN
		subdomains, reset, want bool
		age                     time.Duration
	}{
		{name: "exact", query: "server.corp.ts.net.", want: true},
		{name: "unqueried"},
		{name: "unrelated", query: "other.corp.ts.net."},
		{name: "recent", query: "server.corp.ts.net.", age: negativeCacheLifetime - time.Nanosecond, want: true},
		{name: "expired", query: "server.corp.ts.net.", age: negativeCacheLifetime},
		{name: "subdomain", query: "foo.server.corp.ts.net.", subdomains: true, want: true},
		{name: "nested subdomain", query: "foo.bar.server.corp.ts.net.", subdomains: true, want: true},
		{name: "no subdomain capability", query: "foo.server.corp.ts.net."},
		{name: "label boundary", query: "foo.otherserver.corp.ts.net.", subdomains: true},
		{name: "profile reset", query: "server.corp.ts.net.", reset: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			defer r.Close()
			now := time.Unix(1000, 0)
			r.negativeCache.now = func() time.Time { return now }
			cfg := Config{LocalDomains: []dnsname.FQDN{"corp.ts.net."}}
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
			cfg.Hosts = map[dnsname.FQDN][]netip.Addr{"server.corp.ts.net.": {netip.MustParseAddr("100.64.0.1")}}
			if tt.subdomains {
				cfg.SubdomainHosts = set.Of[dnsname.FQDN]("server.corp.ts.net.")
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
						r.negativeCache.record(dnsname.FQDN(fmt.Sprintf("peer%d-%d.corp.ts.net.", i, j)))
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
			r.negativeCache.record("fresh.corp.ts.net.")
			if r.negativeCache.entries.Len() != 1 {
				t.Fatal("negative after flush was lost")
			}
		})
	}
}

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
			r.negativeCache.record("server.corp.ts.net.")
			now = now.Add(negativeCacheLifetime - time.Second)
			if tt.repeat {
				r.negativeCache.record("server.corp.ts.net.")
			}
			now = now.Add(tt.elapsed)
			if err := r.SetConfig(Config{Hosts: map[dnsname.FQDN][]netip.Addr{"server.corp.ts.net.": {netip.MustParseAddr("100.64.0.1")}}}); err != nil {
				t.Fatal(err)
			}
			if got := r.CheckCachedDNS(); got != tt.want {
				t.Fatalf("flush = %v, want %v", got, tt.want)
			}
		})
	}
}
