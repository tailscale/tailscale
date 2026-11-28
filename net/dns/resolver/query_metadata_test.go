// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"fmt"
	"net/netip"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func TestQueryLocalMetadata(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query []byte
		rcode dns.RCode
	}{
		{"host", dnspacket("test1.ipn.dev.", dns.TypeA, noEdns), dns.RCodeSuccess},
		{"no_data", dnspacket("test1.ipn.dev.", dns.TypeAAAA, noEdns), dns.RCodeSuccess},
		{"nxdomain", dnspacket("missing.ipn.dev.", dns.TypeA, noEdns), dns.RCodeNameError},
		{"reverse", dnspacket(testipv4Arpa, dns.TypePTR, noEdns), dns.RCodeSuccess},
		{"malformed", make([]byte, dnsHeaderLen), dns.RCodeFormatError},
		{"no_upstream", dnspacket("example.com.", dns.TypeA, noEdns), dns.RCodeServerFailure},
		{"blocked_bonjour", dnspacket("b._dns-sd._udp.0.0.10.in-addr.arpa.", dns.TypePTR, noEdns), dns.RCodeNameError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(t)
			t.Cleanup(r.Close)
			if err := r.SetConfig(dnsCfg); err != nil {
				t.Fatal(err)
			}
			res, err := r.Query(t.Context(), tt.query, "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsLocal {
				t.Error("response was not marked local")
			}
			var response dns.Message
			if err := response.Unpack(res.Bs); err != nil {
				t.Fatal(err)
			}
			if response.RCode != tt.rcode {
				t.Errorf("response code = %v, want %v", response.RCode, tt.rcode)
			}
		})
	}
}

func TestQueryForwardedMetadata(t *testing.T) {
	const name dnsname.FQDN = "example.com."
	for _, rcode := range []dns.RCode{dns.RCodeSuccess, dns.RCodeNameError, dns.RCodeServerFailure, dns.RCodeRefused} {
		t.Run(rcode.String(), func(t *testing.T) {
			out, err := (&dns.Message{
				Header: dns.Header{Response: true, RCode: rcode},
				Questions: []dns.Question{{
					Name: dns.MustNewName(string(name)), Type: dns.TypeA, Class: dns.ClassINET,
				}},
			}).Pack()
			if err != nil {
				t.Fatal(err)
			}
			port := runDNSServer(t, nil, out, func(bool, []byte) {})
			r := newResolver(t)
			t.Cleanup(r.Close)
			if err := r.SetConfig(Config{Routes: map[dnsname.FQDN][]*dnstype.Resolver{
				".": {{Addr: fmt.Sprintf("127.0.0.1:%d", port)}},
			}}); err != nil {
				t.Fatal(err)
			}
			res, err := r.Query(t.Context(), dnspacket(name, dns.TypeA, noEdns), "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
			if err != nil {
				t.Fatal(err)
			}
			if res.IsLocal {
				t.Error("forwarded response was marked local")
			}
			var response dns.Message
			if err := response.Unpack(res.Bs); err != nil {
				t.Fatal(err)
			}
			if response.RCode != rcode {
				t.Errorf("response code = %v, want %v", response.RCode, rcode)
			}
		})
	}
}
