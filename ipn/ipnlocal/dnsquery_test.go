// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func TestQueryDNSLocalResolvers(t *testing.T) {
	b := newTestLocalBackend(t)
	dm := b.sys.DNSManager.Get()
	if err := dm.Resolver().SetConfig(resolver.Config{
		Hosts: map[dnsname.FQDN][]netip.Addr{
			"node.tailnet.ts.net.": {netip.MustParseAddr("100.64.0.1")},
		},
		LocalDomains: []dnsname.FQDN{"tailnet.ts.net.", "64.100.in-addr.arpa."},
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			".":                    {{Addr: "192.0.2.53"}},
			"node.tailnet.ts.net.": {{Addr: "192.0.2.54"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		typ   dnsmessage.Type
		rcode dnsmessage.RCode
	}{
		{"node.tailnet.ts.net", dnsmessage.TypeA, dnsmessage.RCodeSuccess},
		{"NODE.TAILNET.TS.NET.", dnsmessage.TypeA, dnsmessage.RCodeSuccess},
		{"node.tailnet.ts.net", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess},
		{"missing.tailnet.ts.net", dnsmessage.TypeA, dnsmessage.RCodeNameError},
		{"1.0.64.100.in-addr.arpa", dnsmessage.TypePTR, dnsmessage.RCodeSuccess},
	} {
		t.Run(tt.name+"/"+tt.typ.String(), func(t *testing.T) {
			out, resolvers, err := b.QueryDNS(t.Context(), tt.name, tt.typ)
			if err != nil {
				t.Fatal(err)
			}
			var response dnsmessage.Message
			if err := response.Unpack(out); err != nil {
				t.Fatal(err)
			}
			if response.RCode != tt.rcode {
				t.Errorf("response code = %v, want %v", response.RCode, tt.rcode)
			}
			if len(resolvers) != 0 {
				t.Errorf("local response reported upstream resolvers: %v", resolvers)
			}
		})
	}
}

func TestQueryDNSForwardedResolvers(t *testing.T) {
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused} {
		t.Run(rcode.String(), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				var query dnsmessage.Message
				if err := query.Unpack(body); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				// An upstream can set AA too; provenance must not depend on it.
				out, err := (&dnsmessage.Message{
					Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RCode: rcode},
					Questions: query.Questions,
				}).Pack()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}))
			t.Cleanup(server.Close)
			b := newTestLocalBackend(t)
			if err := b.sys.DNSManager.Get().Resolver().SetConfig(resolver.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: server.URL}}},
			}); err != nil {
				t.Fatal(err)
			}
			out, resolvers, err := b.QueryDNS(t.Context(), "example.com", dnsmessage.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			var response dnsmessage.Message
			if err := response.Unpack(out); err != nil {
				t.Fatal(err)
			}
			if response.RCode != rcode {
				t.Errorf("response code = %v, want %v", response.RCode, rcode)
			}
			if len(resolvers) != 1 || resolvers[0].Addr != server.URL {
				t.Errorf("forwarded response resolvers = %v, want %q", resolvers, server.URL)
			}
		})
	}
}
