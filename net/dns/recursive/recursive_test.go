// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package recursive

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"slices"

	"github.com/miekg/dns"
	"tailscale.com/envknob"
	"tailscale.com/tstest"
)

const testDomain = "tailscale.com"

// Recursively resolving the AWS console requires being able to handle CNAMEs,
// glue records, falling back from UDP to TCP for oversize queries, and more;
// it's a great integration test for DNS resolution and they can handle the
// traffic :)
const complicatedTestDomain = "console.aws.amazon.com"

var flagNetworkAccess = flag.Bool("enable-network-access", false, "run tests that need external network access")

func init() {
	envknob.Setenv("TS_DEBUG_RECURSIVE_DNS", "true")
}

func newResolver(tb testing.TB) *Resolver {
	clock := tstest.NewClock(tstest.ClockOpts{
		Step: 50 * time.Millisecond,
	})
	return &Resolver{
		Logf:    tb.Logf,
		timeNow: clock.Now,
	}
}

func TestResolve(t *testing.T) {
	if !*flagNetworkAccess {
		t.SkipNow()
	}

	ctx := context.Background()
	r := newResolver(t)
	addrs, minTTL, err := r.Resolve(ctx, testDomain)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("addrs: %+v", addrs)
	t.Logf("minTTL: %v", minTTL)
	if len(addrs) < 1 {
		t.Fatalf("expected at least one address")
	}

	if minTTL <= 10*time.Second || minTTL >= 24*time.Hour {
		t.Errorf("invalid minimum TTL: %v", minTTL)
	}

	var has4, has6 bool
	for _, addr := range addrs {
		has4 = has4 || addr.Is4()
		has6 = has6 || addr.Is6()
	}

	if !has4 {
		t.Errorf("expected at least one IPv4 address")
	}
	if !has6 {
		t.Errorf("expected at least one IPv6 address")
	}
}

func TestResolveComplicated(t *testing.T) {
	if !*flagNetworkAccess {
		t.SkipNow()
	}

	ctx := context.Background()
	r := newResolver(t)
	addrs, minTTL, err := r.Resolve(ctx, complicatedTestDomain)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("addrs: %+v", addrs)
	t.Logf("minTTL: %v", minTTL)
	if len(addrs) < 1 {
		t.Fatalf("expected at least one address")
	}

	if minTTL <= 10*time.Second || minTTL >= 24*time.Hour {
		t.Errorf("invalid minimum TTL: %v", minTTL)
	}
}

func TestResolveNoIPv6(t *testing.T) {
	if !*flagNetworkAccess {
		t.SkipNow()
	}

	r := newResolver(t)
	r.NoIPv6 = true

	addrs, _, err := r.Resolve(context.Background(), testDomain)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("addrs: %+v", addrs)
	if len(addrs) < 1 {
		t.Fatalf("expected at least one address")
	}

	for _, addr := range addrs {
		if addr.Is6() {
			t.Errorf("got unexpected IPv6 address: %v", addr)
		}
	}
}

func TestResolveFallbackToTCP(t *testing.T) {
	var udpCalls, tcpCalls int
	hook := func(nameserver netip.Addr, network string, req *dns.Msg) (*dns.Msg, error) {
		if strings.HasPrefix(network, "udp") {
			t.Logf("got %q query; returning truncated result", network)
			udpCalls++
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.Truncated = true
			return resp, nil
		}

		t.Logf("got %q query; returning real result", network)
		tcpCalls++
		resp := &dns.Msg{}
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: req.Question[0].Qtype,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(1, 2, 3, 4),
		})
		return resp, nil
	}

	r := newResolver(t)
	r.testExchangeHook = hook

	ctx := context.Background()
	resp, err := r.queryNameserverProto(ctx, 0, "tailscale.com", netip.MustParseAddr("9.9.9.9"), "udp", dns.Type(dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Answer) < 1 {
		t.Fatalf("no answers in response: %v", resp)
	}
	rrA, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("invalid RR type: %T", resp.Answer[0])
	}
	if !rrA.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("wanted A response 1.2.3.4, got: %v", rrA.A)
	}
	if tcpCalls != 1 {
		t.Errorf("got %d, want 1 TCP calls", tcpCalls)
	}
	if udpCalls != 1 {
		t.Errorf("got %d, want 1 UDP calls", udpCalls)
	}

	// Verify that we're cached and re-run to fetch from the cache.
	if len(r.queryCache) < 1 {
		t.Errorf("wanted entries in the query cache")
	}

	resp2, err := r.queryNameserverProto(ctx, 0, "tailscale.com", netip.MustParseAddr("9.9.9.9"), "udp", dns.Type(dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp, resp2) {
		t.Errorf("expected equal responses; old=%+v new=%+v", resp, resp2)
	}

	// We didn't make any more network requests since we loaded from the cache.
	if tcpCalls != 1 {
		t.Errorf("got %d, want 1 TCP calls", tcpCalls)
	}
	if udpCalls != 1 {
		t.Errorf("got %d, want 1 UDP calls", udpCalls)
	}
}

func dnsIPRR(name string, addr netip.Addr) dns.RR {
	if addr.Is4() {
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IP(addr.AsSlice()),
		}
	}

	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		AAAA: net.IP(addr.AsSlice()),
	}
}

func cnameRR(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: target,
	}
}

func nsRR(name, target string) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: target,
	}
}

type mockReply struct {
	name  string
	qtype dns.Type
	resp  *dns.Msg
}

type replyMock struct {
	tb      testing.TB
	replies map[netip.Addr][]mockReply
}

func (r *replyMock) exchangeHook(nameserver netip.Addr, network string, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) != 1 {
		r.tb.Fatalf("unsupported multiple or empty question: %v", req.Question)
	}
	question := req.Question[0]

	replies := r.replies[nameserver]
	if len(replies) == 0 {
		r.tb.Fatalf("no configured replies for nameserver: %v", nameserver)
	}

	for _, reply := range replies {
		if reply.name == question.Name && reply.qtype == dns.Type(question.Qtype) {
			return reply.resp.Copy(), nil
		}
	}

	r.tb.Fatalf("no replies found for query %q of type %v to %v", question.Name, question.Qtype, nameserver)
	panic("unreachable")
}

// responses for mocking, shared between the following tests
var (
	rootServerAddr = netip.MustParseAddr("198.41.0.4") // a.root-servers.net.
	comNSAddr      = netip.MustParseAddr("192.5.6.30") // a.gtld-servers.net.

	// DNS response from the root nameservers for a .com nameserver
	comRecord = &dns.Msg{
		Ns:    []dns.RR{nsRR("com.", "a.gtld-servers.net.")},
		Extra: []dns.RR{dnsIPRR("a.gtld-servers.net.", comNSAddr)},
	}

	// Random Amazon nameservers that we use in glue records
	amazonNS   = netip.MustParseAddr("205.251.192.197")
	amazonNSv6 = netip.MustParseAddr("2600:9000:5306:1600::1")

	// Nameservers for the tailscale.com domain
	tailscaleNameservers = &dns.Msg{
		Ns: []dns.RR{
			nsRR("tailscale.com.", "ns-197.awsdns-24.com."),
			nsRR("tailscale.com.", "ns-557.awsdns-05.net."),
			nsRR("tailscale.com.", "ns-1558.awsdns-02.co.uk."),
			nsRR("tailscale.com.", "ns-1359.awsdns-41.org."),
		},
		Extra: []dns.RR{
			dnsIPRR("ns-197.awsdns-24.com.", amazonNS),
		},
	}
)

func TestBasicRecursion(t *testing.T) {
	mock := &replyMock{
		tb: t,
		replies: map[netip.Addr][]mockReply{
			// Query to the root server returns the .com server + a glue record
			rootServerAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},
			},

			// Query to the ".com" server return the nameservers for tailscale.com
			comNSAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
			},

			// Query to the actual nameserver works.
			amazonNS: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{
						dnsIPRR("tailscale.com.", netip.MustParseAddr("13.248.141.131")),
						dnsIPRR("tailscale.com.", netip.MustParseAddr("76.223.15.28")),
					},
				}},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{
						dnsIPRR("tailscale.com.", netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b")),
						dnsIPRR("tailscale.com.", netip.MustParseAddr("2600:9000:a51d:27c1:1530:b9ef:2a6:b9e5")),
					},
				}},
			},
		},
	}

	r := newResolver(t)
	r.testExchangeHook = mock.exchangeHook
	r.rootServers = []netip.Addr{rootServerAddr}

	// Query for tailscale.com, verify we get the right responses
	ctx := context.Background()
	addrs, minTTL, err := r.Resolve(ctx, "tailscale.com")
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := []netip.Addr{
		netip.MustParseAddr("13.248.141.131"),
		netip.MustParseAddr("76.223.15.28"),
		netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b"),
		netip.MustParseAddr("2600:9000:a51d:27c1:1530:b9ef:2a6:b9e5"),
	}
	slices.SortFunc(addrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })
	slices.SortFunc(wantAddrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })

	if !reflect.DeepEqual(addrs, wantAddrs) {
		t.Errorf("got addrs=%+v; want %+v", addrs, wantAddrs)
	}

	const wantMinTTL = 5 * time.Minute
	if minTTL != wantMinTTL {
		t.Errorf("got minTTL=%+v; want %+v", minTTL, wantMinTTL)
	}
}

func TestNoAnswers(t *testing.T) {
	mock := &replyMock{
		tb: t,
		replies: map[netip.Addr][]mockReply{
			// Query to the root server returns the .com server + a glue record
			rootServerAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},
			},

			// Query to the ".com" server return the nameservers for tailscale.com
			comNSAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
			},

			// Query to the actual nameserver returns no responses, authoritatively.
			amazonNS: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{},
				}},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{},
				}},
			},
		},
	}

	r := &Resolver{
		Logf:             t.Logf,
		testExchangeHook: mock.exchangeHook,
		rootServers:      []netip.Addr{rootServerAddr},
	}

	// Query for tailscale.com, verify we get the right responses
	_, _, err := r.Resolve(context.Background(), "tailscale.com")
	if err == nil {
		t.Fatalf("got no error, want error")
	}
	if !errors.Is(err, ErrAuthoritativeNoResponses) {
		t.Fatalf("got err=%v, want %v", err, ErrAuthoritativeNoResponses)
	}
}

func TestRecursionCNAME(t *testing.T) {
	mock := &replyMock{
		tb: t,
		replies: map[netip.Addr][]mockReply{
			// Query to the root server returns the .com server + a glue record
			rootServerAddr: {
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},

				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},
			},

			// Query to the ".com" server return the nameservers for tailscale.com
			comNSAddr: {
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},

				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
			},

			// Query to the actual nameserver works.
			amazonNS: {
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{cnameRR("subdomain.otherdomain.com.", "subdomain.tailscale.com.")},
				}},
				{name: "subdomain.otherdomain.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{cnameRR("subdomain.otherdomain.com.", "subdomain.tailscale.com.")},
				}},

				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{dnsIPRR("tailscale.com.", netip.MustParseAddr("13.248.141.131"))},
				}},
				{name: "subdomain.tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{dnsIPRR("tailscale.com.", netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b"))},
				}},
			},
		},
	}

	r := &Resolver{
		Logf:             t.Logf,
		testExchangeHook: mock.exchangeHook,
		rootServers:      []netip.Addr{rootServerAddr},
	}

	// Query for tailscale.com, verify we get the right responses
	addrs, minTTL, err := r.Resolve(context.Background(), "subdomain.otherdomain.com")
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := []netip.Addr{
		netip.MustParseAddr("13.248.141.131"),
		netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b"),
	}
	slices.SortFunc(addrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })
	slices.SortFunc(wantAddrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })

	if !reflect.DeepEqual(addrs, wantAddrs) {
		t.Errorf("got addrs=%+v; want %+v", addrs, wantAddrs)
	}

	const wantMinTTL = 5 * time.Minute
	if minTTL != wantMinTTL {
		t.Errorf("got minTTL=%+v; want %+v", minTTL, wantMinTTL)
	}
}

func TestRecursionNoGlue(t *testing.T) {
	coukNS := netip.MustParseAddr("213.248.216.1")
	coukRecord := &dns.Msg{
		Ns:    []dns.RR{nsRR("com.", "dns1.nic.uk.")},
		Extra: []dns.RR{dnsIPRR("dns1.nic.uk.", coukNS)},
	}

	intermediateNS := netip.MustParseAddr("205.251.193.66") // g-ns-322.awsdns-02.co.uk.
	intermediateRecord := &dns.Msg{
		Ns:    []dns.RR{nsRR("awsdns-02.co.uk.", "g-ns-322.awsdns-02.co.uk.")},
		Extra: []dns.RR{dnsIPRR("g-ns-322.awsdns-02.co.uk.", intermediateNS)},
	}

	const amazonNameserver = "ns-1558.awsdns-02.co.uk."
	tailscaleNameservers := &dns.Msg{
		Ns: []dns.RR{
			nsRR("tailscale.com.", amazonNameserver),
		},
	}

	tailscaleResponses := []mockReply{
		{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{dnsIPRR("tailscale.com.", netip.MustParseAddr("13.248.141.131"))},
		}},
		{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
			MsgHdr: dns.MsgHdr{Authoritative: true},
			Answer: []dns.RR{dnsIPRR("tailscale.com.", netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b"))},
		}},
	}

	mock := &replyMock{
		tb: t,
		replies: map[netip.Addr][]mockReply{
			rootServerAddr: {
				// Query to the root server returns the .com server + a glue record
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},

				// Querying the .co.uk nameserver returns the .co.uk nameserver + a glue record.
				{name: amazonNameserver, qtype: dns.Type(dns.TypeA), resp: coukRecord},
				{name: amazonNameserver, qtype: dns.Type(dns.TypeAAAA), resp: coukRecord},
			},

			// Queries to the ".com" server return the nameservers
			// for tailscale.com, which don't contain a glue
			// record.
			comNSAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
			},

			// Queries to the ".co.uk" nameserver returns the
			// address of the intermediate Amazon nameserver.
			coukNS: {
				{name: amazonNameserver, qtype: dns.Type(dns.TypeA), resp: intermediateRecord},
				{name: amazonNameserver, qtype: dns.Type(dns.TypeAAAA), resp: intermediateRecord},
			},

			// Queries to the intermediate nameserver returns an
			// answer for the final Amazon nameserver.
			intermediateNS: {
				{name: amazonNameserver, qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{dnsIPRR(amazonNameserver, amazonNS)},
				}},
				{name: amazonNameserver, qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{dnsIPRR(amazonNameserver, amazonNSv6)},
				}},
			},

			// Queries to the actual nameserver work and return
			// responses to the query.
			amazonNS:   tailscaleResponses,
			amazonNSv6: tailscaleResponses,
		},
	}

	r := newResolver(t)
	r.testExchangeHook = mock.exchangeHook
	r.rootServers = []netip.Addr{rootServerAddr}

	// Query for tailscale.com, verify we get the right responses
	addrs, minTTL, err := r.Resolve(context.Background(), "tailscale.com")
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := []netip.Addr{
		netip.MustParseAddr("13.248.141.131"),
		netip.MustParseAddr("2600:9000:a602:b1e6:86d:8165:5e8c:295b"),
	}
	slices.SortFunc(addrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })
	slices.SortFunc(wantAddrs, func(x, y netip.Addr) int { return strings.Compare(x.String(), y.String()) })

	if !reflect.DeepEqual(addrs, wantAddrs) {
		t.Errorf("got addrs=%+v; want %+v", addrs, wantAddrs)
	}

	const wantMinTTL = 5 * time.Minute
	if minTTL != wantMinTTL {
		t.Errorf("got minTTL=%+v; want %+v", minTTL, wantMinTTL)
	}
}

func TestRecursionLimit(t *testing.T) {
	mock := &replyMock{
		tb:      t,
		replies: map[netip.Addr][]mockReply{},
	}

	// Fill out a CNAME chain equal to our recursion limit; we won't get
	// this far since each CNAME is more than 1 level "deep", but this
	// ensures that we have more than the limit.
	for i := range maxDepth + 1 {
		curr := fmt.Sprintf("%d-tailscale.com.", i)

		tailscaleNameservers := &dns.Msg{
			Ns:    []dns.RR{nsRR(curr, "ns-197.awsdns-24.com.")},
			Extra: []dns.RR{dnsIPRR("ns-197.awsdns-24.com.", amazonNS)},
		}

		// Query to the root server returns the .com server + a glue record
		mock.replies[rootServerAddr] = append(mock.replies[rootServerAddr],
			mockReply{name: curr, qtype: dns.Type(dns.TypeA), resp: comRecord},
			mockReply{name: curr, qtype: dns.Type(dns.TypeAAAA), resp: comRecord},
		)

		// Query to the ".com" server return the nameservers for NN-tailscale.com
		mock.replies[comNSAddr] = append(mock.replies[comNSAddr],
			mockReply{name: curr, qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
			mockReply{name: curr, qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
		)

		// Queries to the nameserver return a CNAME for the n+1th server.
		next := fmt.Sprintf("%d-tailscale.com.", i+1)
		mock.replies[amazonNS] = append(mock.replies[amazonNS],
			mockReply{
				name:  curr,
				qtype: dns.Type(dns.TypeA),
				resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{cnameRR(curr, next)},
				},
			},
			mockReply{
				name:  curr,
				qtype: dns.Type(dns.TypeAAAA),
				resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{cnameRR(curr, next)},
				},
			},
		)
	}

	r := newResolver(t)
	r.testExchangeHook = mock.exchangeHook
	r.rootServers = []netip.Addr{rootServerAddr}

	// Query for the first node in the chain, 0-tailscale.com, and verify
	// we get a max-depth error.
	ctx := context.Background()
	_, _, err := r.Resolve(ctx, "0-tailscale.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	} else if !errors.Is(err, ErrMaxDepth) {
		t.Fatalf("got err=%v, want ErrMaxDepth", err)
	}
}

func TestInvalidResponses(t *testing.T) {
	mock := &replyMock{
		tb: t,
		replies: map[netip.Addr][]mockReply{
			// Query to the root server returns the .com server + a glue record
			rootServerAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: comRecord},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: comRecord},
			},

			// Query to the ".com" server return the nameservers for tailscale.com
			comNSAddr: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: tailscaleNameservers},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: tailscaleNameservers},
			},

			// Query to the actual nameserver returns an invalid IP address
			amazonNS: {
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{&dns.A{
						Hdr: dns.RR_Header{
							Name:   "tailscale.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						// Note: this is an IPv6 addr in an IPv4 response
						A: net.IP(netip.MustParseAddr("2600:9000:a51d:27c1:1530:b9ef:2a6:b9e5").AsSlice()),
					}},
				}},
				{name: "tailscale.com.", qtype: dns.Type(dns.TypeAAAA), resp: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					// This an IPv4 response to an IPv6 query
					Answer: []dns.RR{&dns.A{
						Hdr: dns.RR_Header{
							Name:   "tailscale.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.IP(netip.MustParseAddr("13.248.141.131").AsSlice()),
					}},
				}},
			},
		},
	}

	r := &Resolver{
		Logf:             t.Logf,
		testExchangeHook: mock.exchangeHook,
		rootServers:      []netip.Addr{rootServerAddr},
	}

	// Query for tailscale.com, verify we get no responses since the
	// addresses are invalid.
	_, _, err := r.Resolve(context.Background(), "tailscale.com")
	if err == nil {
		t.Fatalf("got no error, want error")
	}
	if !errors.Is(err, ErrAuthoritativeNoResponses) {
		t.Fatalf("got err=%v, want %v", err, ErrAuthoritativeNoResponses)
	}
}

// TODO(andrew): test for more edge cases that aren't currently covered:
//	* Nameservers that cross between IPv4 and IPv6
//	* Authoritative no replies after following CNAME
//	* Authoritative no replies after following non-glue NS record
//	* Error querying non-glue NS record followed by success
