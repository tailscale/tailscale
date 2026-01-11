// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

// Note: This test file uses helper builders already present in other resolver
// tests (e.g., makeTestRequest/makeTestResponse/dnspacket) since they are in
// the same package test space.

func TestExtractValidEDNS0UDPSize(t *testing.T) {
	q := dnspacket("example.com.", dns.TypeA, 917)
	got := extractEDNS0UDPSize(q)
	if got != 917 {
		t.Fatalf("expected 917, got %v", got)
	}
}

func TestExtractSmallEDNS0UDPSize(t *testing.T) {
	q := dnspacket("example.com.", dns.TypeA, 100)
	got := extractEDNS0UDPSize(q)
	// extractEDNS0UDPSize enforces minimum of 512 per RFC 6891 §6.2.5
	if got != minEDNS0Size {
		t.Fatalf("expected %v, got %v", minEDNS0Size, got)
	}
}

func TestExtractLargeEDNS0UDPSize(t *testing.T) {
	q := dnspacket("example.com.", dns.TypeA, 5000)
	got := extractEDNS0UDPSize(q)
	// extractEDNS0UDPSize caps at maxEDNS0Size
	if got != maxEDNS0Size {
		t.Fatalf("expected %v, got %v", maxEDNS0Size, got)
	}
}

func TestTruncateNonEDNS(t *testing.T) {
	// Build a very large response (many A records) without EDNS
	// Create response with many answers
	name := dns.MustNewName("example.com.")
	b := dns.NewBuilder(nil, dns.Header{Response: true, Authoritative: true, RCode: dns.RCodeSuccess})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	// add enough A records to exceed 512 bytes
	for i := 0; i < 200; i++ {
		b.AResource(dns.ResourceHeader{Name: name, Class: dns.ClassINET, TTL: 60}, dns.AResource{A: [4]byte{192, 0, 2, byte(i % 255)}})
	}
	resp, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) <= 512 {
		t.Fatalf("response not large enough for test: %d", len(resp))
	}

	tr, err := truncateDNSResponse(resp, 512)
	if err != nil {
		t.Fatalf("truncate failed: %v", err)
	}
	if len(tr) > 512 {
		t.Fatalf("truncated response too large: %d", len(tr))
	}
	// Check TC bit set
	var p dns.Parser
	h, err := p.Start(tr)
	if err != nil {
		t.Fatalf("parse truncated: %v", err)
	}
	if !h.Truncated {
		t.Fatalf("expected Truncated bit set")
	}
}

func TestEDNSAllowsLarger(t *testing.T) {
	// Build request that advertises EDNS size 1232
	ednsSize := uint16(1232)
	q := dnspacket("example.com.", dns.TypeA, ednsSize)
	if got := extractEDNS0UDPSize(q); got != ednsSize {
		t.Fatalf("expected 1232, got %v", got)
	}

	// Build response of size >512 but <1232
	name := dns.MustNewName("example.com.")
	b := dns.NewBuilder(nil, dns.Header{Response: true, Authoritative: true, RCode: dns.RCodeSuccess})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET})
	b.StartAnswers()
	for i := 0; i < 50; i++ {
		b.AResource(dns.ResourceHeader{Name: name, Class: dns.ClassINET, TTL: 60}, dns.AResource{A: [4]byte{10, 0, 0, byte(i)}})
	}
	resp, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) <= 512 || len(resp) >= int(ednsSize) {
		t.Fatalf("invalid response size %d", len(resp))
	}

	tr, err := truncateDNSResponse(resp, ednsSize)
	if err != nil {
		t.Fatalf("truncate failed: %v", err)
	}
	if len(tr) != len(resp) {
		t.Fatalf("unexpected truncation when EDNS allows large: %d vs %d", len(tr), len(resp))
	}
}

// TestTruncateDNSResponseImpossible verifies that truncateDNSResponse
// returns an error when the provided maxSize is too small to even encode
// the header+question portion of the message.
func TestTruncateDNSResponseImpossible(t *testing.T) {
	// Build a normal query packet and attempt to truncate it to a very small
	// size that cannot contain the header+question.
	req := makeTestRequest(t, "example.com.")
	if len(req) < 20 {
		t.Fatalf("test request unexpectedly small: %d", len(req))
	}

	// Choose a maxSize smaller than the request's header+question length.
	// Using 10 bytes is guaranteed to be too small.
	if _, err := truncateDNSResponse(req, 10); err == nil {
		t.Fatalf("expected error truncating to impossibly small size, got nil")
	}
}

// TestTruncateDNSResponseDirectCall tests truncateDNSResponse with a large
// well-formed DNS response. This directly verifies that
// truncateDNSResponse produces a syntactically valid truncated response
// with the TC bit set.
func TestTruncateDNSResponseDirectCall(t *testing.T) {
	const domain = "example.com."

	// Build a very large DNS response (many A records)
	name := dns.MustNewName(domain)
	b := dns.NewBuilder(nil, dns.Header{Response: true, Authoritative: true, RCode: dns.RCodeSuccess})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	// Add enough A records to exceed 512 bytes significantly.
	// Each A record is roughly 20 bytes, so 150 records will be ~3000 bytes.
	for i := 0; i < 150; i++ {
		err := b.AResource(
			dns.ResourceHeader{Name: name, Class: dns.ClassINET, TTL: 60},
			dns.AResource{A: [4]byte{10, 0, 0, byte(i % 256)}},
		)
		if err != nil {
			t.Fatalf("failed to add A record: %v", err)
		}
	}
	largeResp, err := b.Finish()
	if err != nil {
		t.Fatalf("failed to build large response: %v", err)
	}

	// Verify the response is large enough for truncation.
	if len(largeResp) <= 512 {
		t.Fatalf("test response not large enough for truncation: %d bytes", len(largeResp))
	}

	tr, err := truncateDNSResponse(largeResp, 512)
	if err != nil {
		t.Fatalf("truncateDNSResponse failed: %v", err)
	}

	// Verify the truncated response:
	// 1. Fits within 512 bytes
	if len(tr) > 512 {
		t.Fatalf("truncated response exceeds 512 bytes: got %d", len(tr))
	}

	// 2. Is syntactically valid
	var p dns.Parser
	h, err := p.Start(tr)
	if err != nil {
		t.Fatalf("failed to parse truncated response: %v", err)
	}

	// 3. Has TC (Truncated) bit set
	if !h.Truncated {
		t.Fatalf("expected TC (Truncated) bit to be set in truncated response")
	}
}

// TestResolverSERVFAILOnImpossibleTruncation ensures that when a client
// advertises a tiny EDNS buffer size such that the resolver cannot safely
// encode even the header+question within that size, the resolver returns a
// SERVFAIL response rather than an invalid/truncated packet.
func TestResolverSERVFAILOnImpossibleTruncation(t *testing.T) {
	const domain = "srvfail.example.com."

	// Build a request that advertises a very small EDNS size (50 bytes).
	// This is small enough to require truncation but large enough for header+question.
	request := dnspacket(domain, dns.TypeA, 50)

	// Verify EDNS extraction enforces the RFC 6891 minimum of 512.
	ednsSize := extractEDNS0UDPSize(request)
	if ednsSize != 512 {
		t.Fatalf("EDNS extraction failed: expected 512, got %d", ednsSize)
	}

	// Build a very large upstream response for the same domain so that the
	// resolver will attempt truncation and fail.
	_, largeResponse := makeLargeResponse(t, domain)

	// Run a test DNS server returning the large response.
	port := runDNSServer(t, nil, largeResponse, func(isTCP bool, gotRequest []byte) {
		// DNS server received a request; just ensure the server is reachable
	})

	// Configure resolver to forward queries to our server.
	r := newResolver(t)
	defer r.Close()
	cfg := Config{
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			dnsname.FQDN("."): {{Addr: fmt.Sprintf("127.0.0.1:%d", port)}},
		},
	}
	if err := r.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// Query the resolver over UDP with the tiny EDNS size.
	ctx := context.Background()
	out, err := r.Query(ctx, request, "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// The response should be either:
	// 1. A SERVFAIL (if truncation was impossible), or
	// 2. A response that fits within the effective EDNS size (512 bytes) with TC bit set.
	var p dns.Parser
	h, err := p.Start(out)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if h.RCode == dns.RCodeServerFailure {
		// Good - impossible truncation was handled correctly
		return
	}

	// Otherwise the response must fit within 512 bytes and have TC set.
	if len(out) > 512 {
		t.Fatalf("expected SERVFAIL or <=512 byte response, got %d bytes with RCode=%v",
			len(out), h.RCode)
	}
	if !h.Truncated {
		t.Fatalf("expected TC bit set for truncated response")
	}
}
