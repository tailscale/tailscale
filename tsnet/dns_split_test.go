// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
)

// TestSplitDNSToTailnetResolverUDP resolves a split-DNS name over UDP from a
// node in userspace networking mode, where the upstream resolver is another
// tailnet node. Neither node has a tun device, so the upstream is reachable
// only through netstack. See tailscale/tailscale#20314.
func TestSplitDNSToTailnetResolverUDP(t *testing.T) {
	lt := setupTwoClientTest(t, false) // netstack on both sides; no tun.

	const domain = "e2e.split.example.com."
	const suffix = "split.example.com."
	const upstreamPort = 53
	wantAddr := netip.MustParseAddr("100.101.102.103")

	// This listener lives inside netstack on s1's tailnet address, so s2 can
	// only reach it over the tailnet.
	pc, err := lt.s1.ListenPacket("udp", net.JoinHostPort(lt.s1ip4.String(), fmt.Sprint(upstreamPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go serveOneAnswerDNS(pc, wantAddr)

	// Point split DNS for suffix at s1's tailnet address.
	upstream := netip.AddrPortFrom(lt.s1ip4, upstreamPort)
	if !lt.control.AddRawMapResponse(lt.s2.lb.NodeKey(), &tailcfg.MapResponse{
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				suffix: {{Addr: upstream.String()}},
			},
		},
	}) {
		t.Fatal("AddRawMapResponse failed")
	}

	res := lt.s2.Sys().DNSManager.Get().Resolver()
	if res == nil {
		t.Fatal("s2 has no resolver")
	}
	query := mustDNSQuery(t, domain)
	from := netip.MustParseAddrPort("127.0.0.1:12345")

	// Until the split-DNS route lands the resolver answers immediately with
	// an empty answer section, so wait it out before timing anything below.
	if err := tstest.WaitFor(60*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := res.Query(ctx, query, "udp", from)
		if err != nil {
			return err
		}
		if _, err := firstAAnswer(resp); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for split-DNS route to %v to work: %v", upstream, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := res.Query(ctx, query, "udp", from)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got, err := firstAAnswer(resp)
	if err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if got != wantAddr {
		t.Errorf("answer = %v, want %v", got, wantAddr)
	}
	t.Logf("split-DNS query to a tailnet resolver over netstack UDP took %v", elapsed)

	// An answer is also correct if UDP blackholed and the TCP fallback
	// supplied it, just late: that fallback can't fire before udpRaceTimeout
	// (2s, net/dns/resolver), so bound the time as well as the bytes.
	if elapsed >= 2*time.Second {
		t.Errorf("query took %v (>= 2s): answered by the TCP fallback, not UDP", elapsed)
	}
}

// TestRefusingUpstreamAnswersPromptly checks the whole daemon DNS path — control
// pushing a resolver, dns.Manager, the forwarder — against an upstream that
// answers REFUSED over UDP and accepts TCP without ever answering. The client
// must get the REFUSED, not a stall that ends in no answer at all.
//
// See tailscale/tailscale#20826.
func TestRefusingUpstreamAnswersPromptly(t *testing.T) {
	ctx := t.Context()
	controlURL, control := startControl(t)
	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	// A host-loopback upstream, so this is the ordinary "system upstream" case
	// rather than a tailnet address reached over netstack.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	upstream := netip.MustParseAddrPort(pc.LocalAddr().String())
	go serveRefusedDNS(pc)
	// Bound so the forwarder's TCP retry, if it makes one, connects and then
	// waits rather than failing fast.
	tcpLn, err := net.Listen("tcp", upstream.String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	if !control.AddRawMapResponse(s1.lb.NodeKey(), &tailcfg.MapResponse{
		DNSConfig: &tailcfg.DNSConfig{
			Proxied:   true,
			Resolvers: []*dnstype.Resolver{{Addr: upstream.String()}},
		},
	}) {
		t.Fatal("AddRawMapResponse failed")
	}

	mgr := s1.Sys().DNSManager.Get()
	query := mustDNSQuery(t, "refused.example.com.")
	from := netip.MustParseAddrPort("127.0.0.1:12345")

	// Wait for the pushed resolver to take effect: until it lands there's no
	// upstream at all and the forwarder synthesizes its own SERVFAIL.
	if err := tstest.WaitFor(60*time.Second, func() error {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		resp, err := mgr.Query(ctx, query, "udp", from)
		if err != nil {
			return err
		}
		if got := rcodeOf(t, resp); got != dns.RCodeRefused {
			return fmt.Errorf("rcode = %v, want %v", got, dns.RCodeRefused)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for the REFUSED upstream to take effect: %v", err)
	}

	for i := range 3 {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		start := time.Now()
		resp, err := mgr.Query(ctx, query, "udp", from)
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if got := rcodeOf(t, resp); got != dns.RCodeRefused {
			t.Errorf("query %d: rcode = %v, want %v", i, got, dns.RCodeRefused)
		}
		t.Logf("query %d: %v", i, elapsed)
		// The regression returned nothing after the full 10s dnsQueryTimeout.
		if elapsed >= time.Second {
			t.Errorf("query %d took %v; the upstream's REFUSED should not wait on TCP", i, elapsed)
		}
	}
}

// serveRefusedDNS answers every query on pc with REFUSED, until pc is closed.
func serveRefusedDNS(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}
		var p dns.Parser
		hdr, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		hdr.Response = true
		hdr.RCode = dns.RCodeRefused
		b := dns.NewBuilder(nil, hdr)
		b.StartQuestions()
		b.Question(q)
		resp, err := b.Finish()
		if err != nil {
			continue
		}
		pc.WriteTo(resp, from)
	}
}

// rcodeOf returns the response code in resp.
func rcodeOf(tb testing.TB, resp []byte) dns.RCode {
	tb.Helper()
	var p dns.Parser
	h, err := p.Start(resp)
	if err != nil {
		tb.Fatalf("parsing response: %v", err)
	}
	return h.RCode
}

// serveOneAnswerDNS answers every A query on pc with addr, until pc is closed.
func serveOneAnswerDNS(pc net.PacketConn, addr netip.Addr) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}
		var p dns.Parser
		hdr, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		b := dns.NewBuilder(nil, dns.Header{ID: hdr.ID, Response: true})
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		b.AResource(dns.ResourceHeader{
			Name:  q.Name,
			Class: dns.ClassINET,
			TTL:   300,
		}, dns.AResource{A: addr.As4()})
		resp, err := b.Finish()
		if err != nil {
			continue
		}
		pc.WriteTo(resp, from)
	}
}

// mustDNSQuery builds an A query for domain.
func mustDNSQuery(tb testing.TB, domain string) []byte {
	tb.Helper()
	b := dns.NewBuilder(nil, dns.Header{RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dns.Question{
		Name:  dns.MustNewName(domain),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}); err != nil {
		tb.Fatal(err)
	}
	query, err := b.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return query
}

// firstAAnswer returns the address in resp's first answer record, or an error
// if resp doesn't parse or has no A answer.
func firstAAnswer(resp []byte) (netip.Addr, error) {
	var p dns.Parser
	if _, err := p.Start(resp); err != nil {
		return netip.Addr{}, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, err
	}
	h, err := p.AnswerHeader()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no answer section: %w", err)
	}
	if h.Type != dns.TypeA {
		return netip.Addr{}, fmt.Errorf("answer type = %v, want A", h.Type)
	}
	r, err := p.AResource()
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4(r.A), nil
}
