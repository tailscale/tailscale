// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	dnsmessage "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

func TestSearchCandidates(t *testing.T) {
	search := []dnsname.FQDN{"tail-scale.ts.net.", "corp.example.com."}
	tests := []struct {
		name  string
		host  string
		want  []string
		fails bool
	}{
		{
			name: "single_label",
			host: "foo",
			want: []string{
				"foo.tail-scale.ts.net.",
				"foo.corp.example.com.",
				"foo.",
			},
		},
		{
			name: "single_label_absolute",
			host: "foo.",
			want: []string{"foo."},
		},
		{
			name: "multi_label",
			host: "db.corp",
			want: []string{
				"db.corp.",
				"db.corp.tail-scale.ts.net.",
				"db.corp.corp.example.com.",
			},
		},
		{
			name: "fully_qualified",
			host: "db.corp.example.com",
			want: []string{
				"db.corp.example.com.",
				"db.corp.example.com.tail-scale.ts.net.",
				"db.corp.example.com.corp.example.com.",
			},
		},
		{
			name: "no_search_domains",
			host: "foo",
			want: []string{"foo."},
		},
		{
			name:  "empty",
			host:  "",
			fails: true,
		},
		{
			name:  "invalid",
			host:  "bad name",
			fails: true,
		},
	}
	for _, tt := range tests {
		var sd []dnsname.FQDN
		if tt.name != "no_search_domains" {
			sd = search
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := searchCandidates(tt.host, sd)
			if tt.fails {
				if err == nil {
					t.Fatalf("searchCandidates(%q) = %v; want error", tt.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("searchCandidates(%q): %v", tt.host, err)
			}
			var gotStrs []string
			for _, fqdn := range got {
				gotStrs = append(gotStrs, string(fqdn))
			}
			if !slices.Equal(gotStrs, tt.want) {
				t.Errorf("searchCandidates(%q) = %v; want %v", tt.host, gotStrs, tt.want)
			}
		})
	}
}

func TestSearchDomainsFromNetmap(t *testing.T) {
	node := func(name string) tailcfg.NodeView {
		return (&tailcfg.Node{Name: name}).View()
	}
	tests := []struct {
		name string
		nm   *netmap.NetworkMap
		want []string
	}{
		{
			name: "nil",
			nm:   nil,
			want: nil,
		},
		{
			name: "magicdns_on_includes_suffix",
			nm: &netmap.NetworkMap{
				SelfNode: node("host.tail-scale.ts.net."),
				DNS: tailcfg.DNSConfig{
					Proxied: true,
					Domains: []string{"tail-scale.ts.net", "corp.example.com"},
				},
			},
			want: []string{"tail-scale.ts.net.", "corp.example.com."},
		},
		{
			name: "magicdns_on_omits_suffix",
			nm: &netmap.NetworkMap{
				SelfNode: node("host.tail-scale.ts.net."),
				DNS: tailcfg.DNSConfig{
					Proxied: true,
					Domains: []string{"corp.example.com"},
				},
			},
			want: []string{"corp.example.com.", "tail-scale.ts.net."},
		},
		{
			name: "magicdns_off_suffix_not_added",
			nm: &netmap.NetworkMap{
				SelfNode: node("host.tail-scale.ts.net."),
				DNS: tailcfg.DNSConfig{
					Proxied: false,
					Domains: []string{"corp.example.com"},
				},
			},
			want: []string{"corp.example.com."},
		},
		{
			name: "dedupes_and_lowercases",
			nm: &netmap.NetworkMap{
				SelfNode: node("host.tail-scale.ts.net."),
				DNS: tailcfg.DNSConfig{
					Proxied: true,
					Domains: []string{"Corp.Example.COM", "corp.example.com", "."},
				},
			},
			want: []string{"corp.example.com.", "tail-scale.ts.net."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := searchDomainsFromNetmap(tt.nm)
			var gotStrs []string
			for _, fqdn := range got {
				gotStrs = append(gotStrs, string(fqdn))
			}
			if !slices.Equal(gotStrs, tt.want) {
				t.Errorf("SearchDomainsFromNetmap = %v; want %v", gotStrs, tt.want)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	name, err := dnsmessage.NewName("foo.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}

	build := func(mutate func(*dnsmessage.Header), answers ...dnsmessage.Resource) []byte {
		t.Helper()
		hdr := dnsmessage.Header{ID: 42, Response: true, RecursionDesired: true}
		mutate(&hdr)
		b := dnsmessage.NewBuilder(nil, hdr)
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		if err := b.Question(question); err != nil {
			t.Fatal(err)
		}
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		for _, rr := range answers {
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				if err := b.AResource(rr.Header, *body); err != nil {
					t.Fatal(err)
				}
			case *dnsmessage.AAAAResource:
				if err := b.AAAAResource(rr.Header, *body); err != nil {
					t.Fatal(err)
				}
			case *dnsmessage.PTRResource:
				if err := b.PTRResource(rr.Header, *body); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unhandled resource body %T", rr.Body)
			}
		}
		out, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	aHeader := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5}
	var fqdn dnsname.FQDN = "foo.example.com."
	parse := func(msg []byte) queryResult {
		return parseResponse(msg, fqdn, dnsmessage.TypeA)
	}

	t.Run("answers", func(t *testing.T) {
		got := parse(build(func(*dnsmessage.Header) {}, dnsmessage.Resource{
			Header: aHeader,
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
		}))
		if got.err != nil || got.notFound || got.servfail {
			t.Fatalf("parseResponse = %+v; want success", got)
		}
		want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
		if !slices.Equal(got.ips, want) {
			t.Errorf("ips = %v; want %v", got.ips, want)
		}
	})
	t.Run("no_data", func(t *testing.T) {
		if got := parse(build(func(*dnsmessage.Header) {})); !got.notFound {
			t.Errorf("parseResponse = %+v; want notFound", got)
		}
	})
	t.Run("nxdomain", func(t *testing.T) {
		got := parse(build(func(h *dnsmessage.Header) { h.RCode = dnsmessage.RCodeNameError }))
		if !got.notFound {
			t.Errorf("parseResponse = %+v; want notFound", got)
		}
	})
	t.Run("servfail", func(t *testing.T) {
		got := parse(build(func(h *dnsmessage.Header) { h.RCode = dnsmessage.RCodeServerFailure }))
		if !got.servfail {
			t.Errorf("parseResponse = %+v; want servfail", got)
		}
	})
	t.Run("refused", func(t *testing.T) {
		got := parse(build(func(h *dnsmessage.Header) { h.RCode = dnsmessage.RCodeRefused }))
		if !got.servfail {
			t.Errorf("parseResponse = %+v; want servfail", got)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		got := parse(build(func(h *dnsmessage.Header) { h.Truncated = true },
			dnsmessage.Resource{Header: aHeader, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}))
		if got.err == nil {
			t.Errorf("parseResponse = %+v; want error", got)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if got := parse([]byte("not a dns response")); got.err == nil {
			t.Errorf("parseResponse = %+v; want error", got)
		}
	})
	t.Run("ptr_ignored", func(t *testing.T) {
		ptrName, err := dnsmessage.NewName("foo.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
		hdr := dnsmessage.Header{ID: 42, Response: true}
		b := dnsmessage.NewBuilder(nil, hdr)
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		if err := b.Question(question); err != nil {
			t.Fatal(err)
		}
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		ptrHeader := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 5}
		if err := b.PTRResource(ptrHeader, dnsmessage.PTRResource{PTR: ptrName}); err != nil {
			t.Fatal(err)
		}
		msg, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		got := parseResponse(msg, fqdn, dnsmessage.TypeA)
		if got.err != nil || !got.notFound || len(got.ips) != 0 {
			t.Errorf("parseResponse = %+v; want PTR record ignored", got)
		}
	})

	t.Run("wrong_question_name", func(t *testing.T) {
		other, err := dnsmessage.NewName("other.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, Response: true})
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		if err := b.Question(dnsmessage.Question{Name: other, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatal(err)
		}
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		if err := b.AResource(aHeader, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}); err != nil {
			t.Fatal(err)
		}
		msg, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		if got := parse(msg); got.err == nil {
			t.Errorf("parse = %+v; want question-mismatch error", got)
		}
	})

	t.Run("wrong_record_type_ignored", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, Response: true})
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatal(err)
		}
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		if err := b.AResource(aHeader, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}); err != nil {
			t.Fatal(err)
		}
		msg, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		got := parseResponse(msg, fqdn, dnsmessage.TypeAAAA)
		if got.err != nil || len(got.ips) != 0 || !got.notFound {
			t.Errorf("parse(AAAA) = %+v; want notFound with no ips", got)
		}
	})
}

// TestDNSResolverFakeQuery checks search order, host fallback, and DNS errors.
func TestDNSResolverFakeQuery(t *testing.T) {
	type answer struct {
		rcode dnsmessage.RCode
		ips   []netip.Addr // A records for NOERROR responses
	}
	// fake returns answers keyed by names without trailing dots.
	// Missing names return authoritative NOERROR with no records.
	fake := func(routedSuffix string, answers map[string]answer) func(context.Context, dnsname.FQDN, dnsmessage.Type) ([]byte, bool, error) {
		return func(_ context.Context, name dnsname.FQDN, qtype dnsmessage.Type) ([]byte, bool, error) {
			routed := routedSuffix != "" && dnsname.FQDN(routedSuffix).Contains(name)
			n, err := dnsmessage.NewName(name.WithTrailingDot())
			if err != nil {
				return nil, routed, err
			}
			a := answers[name.WithoutTrailingDot()]
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true, RCode: a.rcode})
			if err := b.StartQuestions(); err != nil {
				return nil, routed, err
			}
			if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
				return nil, routed, err
			}
			if err := b.StartAnswers(); err != nil {
				return nil, routed, err
			}
			if a.rcode == dnsmessage.RCodeSuccess {
				rh := dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5}
				for _, ip := range a.ips {
					if !ip.Is4() {
						continue
					}
					if err := b.AResource(rh, dnsmessage.AResource{A: ip.As4()}); err != nil {
						return nil, routed, err
					}
				}
			}
			out, err := b.Finish()
			return out, routed, err
		}
	}

	search := func() []dnsname.FQDN {
		return []dnsname.FQDN{"tail-scale.ts.net.", "corp.example.com."}
	}
	wantIP := netip.MustParseAddr("192.0.2.1")

	t.Run("search_iterates_past_no_data", func(t *testing.T) {
		c := &dnsResolver{
			queryDNS: fake("corp.example.com.", map[string]answer{
				"foo.corp.example.com": {ips: []netip.Addr{wantIP}},
			}),
			searchDomains: search,
		}
		ips, err := c.lookupIP(t.Context(), "ip4", "foo")
		if err != nil || len(ips) != 1 || ips[0] != wantIP {
			t.Errorf("LookupIP(foo) = %v, %v; want %v", ips, err, wantIP)
		}
	})

	t.Run("routed_servfail_stands", func(t *testing.T) {
		c := &dnsResolver{
			queryDNS: fake("corp.example.com.", map[string]answer{
				"db.corp.example.com": {rcode: dnsmessage.RCodeServerFailure},
			}),
		}
		_, err := c.lookupIP(t.Context(), "ip4", "db.corp.example.com")
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || dnsErr.IsNotFound || dnsErr.Err != "server misbehaving" {
			t.Errorf("LookupIP error = %v; want temporary server misbehaving", err)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		c := &dnsResolver{
			queryDNS: fake("corp.example.com.", map[string]answer{
				"db.corp.example.com": {rcode: dnsmessage.RCodeNameError},
			}),
			searchDomains: search,
		}
		_, err := c.lookupIP(t.Context(), "ip4", "db.corp.example.com")
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Errorf("LookupIP error = %v; want not-found", err)
		}
	})

	t.Run("literals", func(t *testing.T) {
		c := &dnsResolver{queryDNS: fake("", nil)}
		ips, err := c.lookupIP(t.Context(), "ip", "192.0.2.1")
		if err != nil || len(ips) != 1 || ips[0] != wantIP {
			t.Errorf("LookupIP(192.0.2.1) = %v, %v", ips, err)
		}
		if _, err := c.lookupIP(t.Context(), "ip4", "2001:db8::1"); err == nil {
			t.Errorf("LookupIP(ip4, 2001:db8::1) = nil error; want family mismatch")
		}
	})
}

// buildBenchmarkResponse returns a wire-format NOERROR response with one
// A or AAAA record.
func buildBenchmarkResponse(b *testing.B, qtype dnsmessage.Type, ip netip.Addr) []byte {
	b.Helper()
	name, err := dnsmessage.NewName("db.corp.example.com.")
	if err != nil {
		b.Fatal(err)
	}
	q := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	hdr := dnsmessage.Header{ID: 1, Response: true, RecursionDesired: true}
	bd := dnsmessage.NewBuilder(nil, hdr)
	if err := bd.StartQuestions(); err != nil {
		b.Fatal(err)
	}
	if err := bd.Question(q); err != nil {
		b.Fatal(err)
	}
	if err := bd.StartAnswers(); err != nil {
		b.Fatal(err)
	}
	rh := dnsmessage.ResourceHeader{Name: name, Type: qtype, Class: dnsmessage.ClassINET, TTL: 60}
	if qtype == dnsmessage.TypeA {
		if err := bd.AResource(rh, dnsmessage.AResource{A: ip.As4()}); err != nil {
			b.Fatal(err)
		}
	} else {
		if err := bd.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip.As16()}); err != nil {
			b.Fatal(err)
		}
	}
	out, err := bd.Finish()
	if err != nil {
		b.Fatal(err)
	}
	return out
}

// TestDNSResolverRoutedErrorNoHostFallback verifies that routed queries
// return transport errors without host fallback.
func TestDNSResolverRoutedErrorNoHostFallback(t *testing.T) {
	sentinel := errors.New("upstream unreachable")
	c := &dnsResolver{
		queryDNS: func(context.Context, dnsname.FQDN, dnsmessage.Type) ([]byte, bool, error) {
			return nil, true, sentinel
		},
	}
	_, err := c.lookupIP(t.Context(), "ip4", "db.corp.example.com.")
	if !errors.Is(err, sentinel) {
		t.Errorf("LookupIP error = %v; want the query error (no host fallback)", err)
	}
}

// TestDNSResolverContextPropagation verifies that the caller's deadline
// bounds queryDNS.
func TestDNSResolverContextPropagation(t *testing.T) {
	c := &dnsResolver{
		queryDNS: func(ctx context.Context, _ dnsname.FQDN, _ dnsmessage.Type) ([]byte, bool, error) {
			<-ctx.Done()
			return nil, false, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.lookupIP(ctx, "ip4", "db.corp.example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupIP error = %v; want the caller deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("LookupIP took %v; want it to honor the caller deadline", elapsed)
	}
}

// TestDNSResolverErrorClassification checks errors for mixed address-family
// results and cancellation.
func TestDNSResolverErrorClassification(t *testing.T) {
	nxdomain := func(name string) ([]byte, bool, error) {
		n, err := dnsmessage.NewName(name)
		if err != nil {
			return nil, false, err
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: dnsmessage.RCodeNameError})
		if err := b.StartQuestions(); err != nil {
			return nil, false, err
		}
		if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			return nil, false, err
		}
		if err := b.StartAnswers(); err != nil {
			return nil, false, err
		}
		out, err := b.Finish()
		return out, true, err
	}

	t.Run("canceled_not_timeout", func(t *testing.T) {
		c := &dnsResolver{
			queryDNS: func(ctx context.Context, _ dnsname.FQDN, _ dnsmessage.Type) ([]byte, bool, error) {
				return nil, true, context.Canceled
			},
		}
		_, err := c.lookupIP(t.Context(), "ip4", "db.corp.example.com")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v; want the wrapped context.Canceled", err)
		}
	})

	t.Run("deadline_is_timeout", func(t *testing.T) {
		c := &dnsResolver{
			queryDNS: func(ctx context.Context, _ dnsname.FQDN, _ dnsmessage.Type) ([]byte, bool, error) {
				return nil, true, context.DeadlineExceeded
			},
		}
		_, err := c.lookupIP(t.Context(), "ip4", "db.corp.example.com")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v; want the wrapped deadline", err)
		}
	})

	t.Run("mixed_family_keeps_error", func(t *testing.T) {
		// The AAAA query's deadline error takes precedence over the A
		// query's authoritative NXDOMAIN.
		c := &dnsResolver{
			queryDNS: func(_ context.Context, name dnsname.FQDN, qtype dnsmessage.Type) ([]byte, bool, error) {
				if qtype == dnsmessage.TypeAAAA {
					return nil, true, context.DeadlineExceeded
				}
				return nxdomain(name.WithTrailingDot())
			},
		}
		_, err := c.lookupIP(t.Context(), "ip", "db.corp.example.com")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("mixed-family error = %v; want the deadline to win over the NXDOMAIN", err)
		}
	})
}

// TestHostFallbackName checks that only bare single-label names allow
// host search expansion. All other candidates keep their trailing dots.
func TestHostFallbackName(t *testing.T) {
	tests := []struct {
		candidate string
		host      string
		want      string
	}{
		{candidate: "db.corp.example.com.", host: "db", want: "db.corp.example.com."},
		{candidate: "db.corp.", host: "db.corp", want: "db.corp."},
		{candidate: "foo.", host: "foo.", want: "foo."}, // trailing dot prevents expansion
		{candidate: "foo.", host: "foo", want: "foo"},   // host search expansion allowed
		{candidate: "Foo.", host: "Foo", want: "Foo"},
		{candidate: "db.tail-scale.ts.net.", host: "db", want: "db.tail-scale.ts.net."},
	}
	for _, tt := range tests {
		if got := hostFallbackName(dnsname.FQDN(tt.candidate), tt.host); got != tt.want {
			t.Errorf("hostFallbackName(%q, %q) = %q; want %q", tt.candidate, tt.host, got, tt.want)
		}
	}
}

// BenchmarkLookupIP measures search expansion, parallel A/AAAA queries, and
// response parsing with prebuilt query responses.
func BenchmarkLookupIP(b *testing.B) {
	aResp := buildBenchmarkResponse(b, dnsmessage.TypeA, netip.MustParseAddr("192.0.2.10"))
	aaaaResp := buildBenchmarkResponse(b, dnsmessage.TypeAAAA, netip.MustParseAddr("2001:db8::10"))
	search := []dnsname.FQDN{"tail-scale.ts.net.", "corp.example.com."}
	c := &dnsResolver{
		queryDNS: func(_ context.Context, _ dnsname.FQDN, qtype dnsmessage.Type) ([]byte, bool, error) {
			if qtype == dnsmessage.TypeA {
				return aResp, true, nil
			}
			return aaaaResp, true, nil
		},
		searchDomains: func() []dnsname.FQDN { return search },
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ips, err := c.lookupIP(ctx, "ip", "db")
		if err != nil {
			b.Fatal(err)
		}
		if len(ips) != 2 {
			b.Fatalf("ips = %v", ips)
		}
	}
}
