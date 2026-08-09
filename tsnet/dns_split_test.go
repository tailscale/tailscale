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
