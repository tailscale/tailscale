// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package dnstest provides helpers shared by DNS-related tests.
package dnstest

import (
	"context"
	"net/netip"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
)

// RequireNXDOMAIN issues an IN A query for name over UDP using query and fails
// the test immediately if the query fails or the response is not NXDOMAIN.
// query can be a DNS manager's Query method.
func RequireNXDOMAIN(t testing.TB, query func(context.Context, []byte, string, netip.AddrPort) ([]byte, error), name string) {
	t.Helper()
	qname, err := dns.NewName(name)
	if err != nil {
		t.Fatalf("invalid DNS name %q: %v", name, err)
	}
	packet, err := (&dns.Message{
		Header: dns.Header{ID: 1},
		Questions: []dns.Question{{
			Name:  qname,
			Type:  dns.TypeA,
			Class: dns.ClassINET,
		}},
	}).Pack()
	if err != nil {
		t.Fatalf("packing DNS query for %q: %v", name, err)
	}
	out, err := query(t.Context(), packet, "udp", netip.MustParseAddrPort("100.64.0.1:12345"))
	if err != nil {
		t.Fatalf("querying %q: %v", name, err)
	}
	var response dns.Message
	if err := response.Unpack(out); err != nil {
		t.Fatalf("unpacking DNS response for %q: %v", name, err)
	}
	if response.RCode != dns.RCodeNameError {
		t.Fatalf("DNS response for %q: rcode = %v, want NXDOMAIN", name, response.RCode)
	}
}
