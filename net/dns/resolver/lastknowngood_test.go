// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func mustFQDN(tb testing.TB, s string) dnsname.FQDN {
	tb.Helper()
	f, err := dnsname.ToFQDN(s)
	if err != nil {
		tb.Fatal(err)
	}
	return f
}

// makeTestAAAAResponse builds a Type AAAA response; makeTestResponse only
// handles A records.
func makeTestAAAAResponse(tb testing.TB, domain string, code dns.RCode, addrs ...netip.Addr) []byte {
	tb.Helper()
	name := dns.MustNewName(domain)
	b := dns.NewBuilder(nil, dns.Header{Response: true, Authoritative: true, RCode: code})
	b.StartQuestions()
	q := dns.Question{Name: name, Type: dns.TypeAAAA, Class: dns.ClassINET}
	b.Question(q)
	if len(addrs) > 0 {
		b.StartAnswers()
		for _, a := range addrs {
			b.AAAAResource(dns.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120}, dns.AAAAResource{AAAA: a.As16()})
		}
	}
	resp, err := b.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return resp
}

func TestIsSinkholeResponse(t *testing.T) {
	const domain = "console.tailscale.com."
	tests := []struct {
		name string
		resp []byte
		want bool
	}{
		{
			name: "all zero A",
			resp: makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified()),
			want: true,
		},
		{
			name: "zero AAAA",
			resp: makeTestAAAAResponse(t, domain, dns.RCodeSuccess, netip.IPv6Unspecified()),
			want: true,
		},
		{
			name: "real A",
			resp: makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("100.64.0.1")),
			want: false,
		},
		{
			name: "mixed real and zero",
			resp: makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified(), netip.MustParseAddr("100.64.0.1")),
			want: false,
		},
		{
			name: "no-data NOERROR",
			resp: makeTestResponse(t, domain, dns.RCodeSuccess),
			want: false,
		},
		{
			name: "nxdomain",
			resp: makeTestResponse(t, domain, dns.RCodeNameError),
			want: false,
		},
		{
			name: "servfail",
			resp: makeTestResponse(t, domain, dns.RCodeServerFailure),
			want: false,
		},
		{
			name: "garbage",
			resp: []byte{0x00, 0x01, 0x02},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSinkholeResponse(tt.resp); got != tt.want {
				t.Errorf("isSinkholeResponse = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResponseHasRealAddr(t *testing.T) {
	const domain = "console.tailscale.com."
	tests := []struct {
		name string
		resp []byte
		want bool
	}{
		{"real A", makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("100.64.0.1")), true},
		{"zero A", makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified()), false},
		{"mixed", makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified(), netip.MustParseAddr("100.64.0.1")), true},
		{"no-data", makeTestResponse(t, domain, dns.RCodeSuccess), false},
		{"nxdomain", makeTestResponse(t, domain, dns.RCodeNameError), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseHasRealAddr(tt.resp); got != tt.want {
				t.Errorf("responseHasRealAddr = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLastKnownGoodAllowlist(t *testing.T) {
	c := &lastKnownGood{suffixes: parseLKGDomains("tailscale.com,example.org")}
	tests := []struct {
		name string
		want bool
	}{
		{"tailscale.com.", true},
		{"console.tailscale.com.", true},
		{"login.tailscale.com.", true},
		{"example.org.", true},
		{"sub.example.org.", true},
		{"nottailscale.com.", false},
		{"tailscale.com.evil.com.", false},
		{"google.com.", false},
	}
	for _, tt := range tests {
		if got := c.allowed(mustFQDN(t, tt.name)); got != tt.want {
			t.Errorf("allowed(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseLKGDomains(t *testing.T) {
	// Unset uses the default.
	if got := parseLKGDomains(""); len(got) != 1 || got[0] != mustFQDN(t, "tailscale.com") {
		t.Errorf("parseLKGDomains(%q) = %v, want [tailscale.com.]", "", got)
	}
	// Explicitly blank disables.
	if got := parseLKGDomains("   "); len(got) != 0 {
		t.Errorf("parseLKGDomains(%q) = %v, want empty", "   ", got)
	}
	// Multiple with junk entries skipped.
	got := parseLKGDomains("a.com, , b.com")
	if len(got) != 2 || got[0] != mustFQDN(t, "a.com") || got[1] != mustFQDN(t, "b.com") {
		t.Errorf("parseLKGDomains = %v, want [a.com. b.com.]", got)
	}
}

func TestLastKnownGoodStoreLookup(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := &lastKnownGood{
		suffixes: parseLKGDomains("tailscale.com"),
		now:      func() time.Time { return now },
	}
	const domain = "console.tailscale.com."
	name := mustFQDN(t, domain)
	real := makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("100.64.0.1"))

	// Not allowlisted: store is a no-op, lookup misses.
	other := mustFQDN(t, "notus.com.")
	c.store(other, dns.TypeA, real)
	if _, ok := c.lookup(other, dns.TypeA, 1234); ok {
		t.Fatal("expected miss for non-allowlisted name")
	}

	// Store then look up with a patched txid.
	c.store(name, dns.TypeA, bytes.Clone(real))
	got, ok := c.lookup(name, dns.TypeA, 0xBEEF)
	if !ok {
		t.Fatal("expected hit after store")
	}
	if getTxID(got) != 0xBEEF {
		t.Errorf("cached txid = %v, want 0xBEEF", getTxID(got))
	}
	// Other fields (rcode, answer) should be intact.
	if !responseHasRealAddr(got) {
		t.Error("cached response lost its real address")
	}

	// Different type misses.
	if _, ok := c.lookup(name, dns.TypeAAAA, 1); ok {
		t.Error("expected miss for different qtype")
	}

	// Expires after TTL.
	now = now.Add(lkgTTL + time.Second)
	if _, ok := c.lookup(name, dns.TypeA, 1); ok {
		t.Error("expected miss after TTL expiry")
	}
}

// runQueryOnForwarder sends one query through an existing forwarder against the
// given resolver ports, so tests can reuse a forwarder (and thus its cache)
// across multiple queries.
func runQueryOnForwarder(tb testing.TB, fwd *forwarder, request []byte, ports ...uint16) ([]byte, error) {
	tb.Helper()
	resolvers := make([]resolverAndDelay, len(ports))
	for i, port := range ports {
		resolvers[i].name = &dnstype.Resolver{Addr: fmt.Sprintf("127.0.0.1:%d", port)}
	}
	rpkt := packet{bs: request, family: "udp", addr: netip.MustParseAddrPort("127.0.0.1:12345")}
	rchan := make(chan packet, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	tb.Cleanup(cancel)
	err := fwd.forwardWithDestChan(ctx, rpkt, rchan, resolvers...)
	select {
	case res := <-rchan:
		return res.bs, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestForwarderLKGServesSinkhole primes the cache with a real answer, then
// confirms a later sinkhole for the same allowlisted name is replaced with the
// cached address.
func TestForwarderLKGServesSinkhole(t *testing.T) {
	const domain = "console.tailscale.com."
	request := makeTestRequest(t, domain, dns.TypeA, 0)
	realAddr := netip.MustParseAddr("100.64.0.1")
	real := makeTestResponse(t, domain, dns.RCodeSuccess, realAddr)
	sinkhole := makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified())

	realPort := runDNSServer(t, nil, real, func(bool, []byte) {})
	sinkPort := runDNSServer(t, nil, sinkhole, func(bool, []byte) {})

	fwd := newTestForwarder(t, nil)

	// Prime from the honest resolver.
	resp, err := runQueryOnForwarder(t, fwd, request, realPort)
	if err != nil {
		t.Fatalf("priming query: %v", err)
	}
	if !responseHasRealAddr(resp) {
		t.Fatalf("priming query did not return a real address")
	}

	// Now only the sinkholing resolver is reachable; expect the cached answer.
	resp, err = runQueryOnForwarder(t, fwd, request, sinkPort)
	if err != nil {
		t.Fatalf("sinkhole query: %v", err)
	}
	if isSinkholeResponse(resp) {
		t.Fatalf("got sinkhole response, want cached real address")
	}
	if !responseHasRealAddr(resp) {
		t.Fatalf("cached response lacks a real address")
	}
	if getTxID(resp) != getTxID(request) {
		t.Errorf("response txid = %v, want %v (request txid)", getTxID(resp), getTxID(request))
	}
}

// TestForwarderLKGNonAllowlistedPassesThrough confirms a sinkhole for a name
// outside the allowlist is delivered as-is, even if it was once cached-eligible.
func TestForwarderLKGNonAllowlistedPassesThrough(t *testing.T) {
	const domain = "example.com."
	request := makeTestRequest(t, domain, dns.TypeA, 0)
	real := makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("93.184.216.34"))
	sinkhole := makeTestResponse(t, domain, dns.RCodeSuccess, netip.IPv4Unspecified())

	realPort := runDNSServer(t, nil, real, func(bool, []byte) {})
	sinkPort := runDNSServer(t, nil, sinkhole, func(bool, []byte) {})

	fwd := newTestForwarder(t, nil)

	if _, err := runQueryOnForwarder(t, fwd, request, realPort); err != nil {
		t.Fatalf("priming query: %v", err)
	}
	resp, err := runQueryOnForwarder(t, fwd, request, sinkPort)
	if err != nil {
		t.Fatalf("sinkhole query: %v", err)
	}
	if !isSinkholeResponse(resp) {
		t.Errorf("non-allowlisted sinkhole was altered; want pass-through")
	}
}

// TestForwarderLKGServesOnForwardFailure confirms a cached answer is served when
// forwarding fails entirely (here: an upstream SERVFAIL) for an allowlisted name.
func TestForwarderLKGServesOnForwardFailure(t *testing.T) {
	const domain = "login.tailscale.com."
	request := makeTestRequest(t, domain, dns.TypeA, 0)
	real := makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("100.64.0.2"))
	servfail := makeTestResponse(t, domain, dns.RCodeServerFailure)

	realPort := runDNSServer(t, nil, real, func(bool, []byte) {})
	failPort := runDNSServer(t, nil, servfail, func(bool, []byte) {})

	fwd := newTestForwarder(t, nil)

	if _, err := runQueryOnForwarder(t, fwd, request, realPort); err != nil {
		t.Fatalf("priming query: %v", err)
	}
	resp, err := runQueryOnForwarder(t, fwd, request, failPort)
	if err != nil {
		t.Fatalf("failing query: %v", err)
	}
	if getRCode(resp) != dns.RCodeSuccess {
		t.Fatalf("got rcode %v, want success from cache", getRCode(resp))
	}
	if !responseHasRealAddr(resp) {
		t.Errorf("cached response lacks a real address")
	}
}
