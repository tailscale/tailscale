// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/httpm"
)

var testDoH = flag.Bool("test-doh", false, "do real DoH tests against the network")

const someDNSID = 123 // something non-zero as a test; in violation of spec's SHOULD of 0

func someDNSQuestion(t testing.TB) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0, // query
		RecursionDesired: true,
		ID:               someDNSID,
	})
	b.StartQuestions() // err
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("tailscale.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestDoH(t *testing.T) {
	if !*testDoH {
		t.Skip("skipping manual test without --test-doh flag")
	}
	prefixes := publicdns.KnownDoHPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("no known DoH")
	}

	f := &forwarder{}

	for _, urlBase := range prefixes {
		t.Run(urlBase, func(t *testing.T) {
			c, ok := f.getKnownDoHClientForProvider(urlBase)
			if !ok {
				t.Fatal("expected DoH")
			}
			res, err := f.sendDoH(context.Background(), urlBase, c, someDNSQuestion(t))
			if err != nil {
				t.Fatal(err)
			}
			c.Transport.(*http.Transport).CloseIdleConnections()

			var p dnsmessage.Parser
			h, err := p.Start(res)
			if err != nil {
				t.Fatal(err)
			}
			if h.ID != someDNSID {
				t.Errorf("response DNS ID = %v; want %v", h.ID, someDNSID)
			}

			p.SkipAllQuestions()
			aa, err := p.AllAnswers()
			if err != nil {
				t.Fatal(err)
			}
			if len(aa) == 0 {
				t.Fatal("no answers")
			}
			for _, r := range aa {
				t.Logf("got: %v", r.GoString())
			}
		})
	}
}

func TestDoHV6Fallback(t *testing.T) {
	for _, base := range publicdns.KnownDoHPrefixes() {
		for _, ip := range publicdns.DoHIPsOfBase(base) {
			if ip.Is4() {
				ip6, ok := publicdns.DoHV6(base)
				if !ok {
					t.Errorf("no v6 DoH known for %v", ip)
				} else if !ip6.Is6() {
					t.Errorf("dohV6(%q) returned non-v6 address %v", base, ip6)
				}
			}
		}
	}
}

func TestGetDoHClientForResolver(t *testing.T) {
	var fwd forwarder

	// Known public providers work without a bootstrap resolution.
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: "https://dns.google/dns-query"}); !ok {
		t.Fatal("known provider without bootstrap not ok")
	}

	// Arbitrary providers with a hostname require a bootstrap resolution: we
	// cannot resolve the DoH server's own name without recursing through
	// ourselves.
	arbitrary := "https://doh.corp.example/query"
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary}); ok {
		t.Fatal("arbitrary provider without bootstrap unexpectedly ok")
	}

	// A URL whose host is an IP literal dials itself; no bootstrap resolution
	// is needed.
	for _, ipURL := range []string{
		"https://192.0.2.53:8443/dns-query",
		"https://[2001:db8::53]/dns-query",
	} {
		if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: ipURL}); !ok {
			t.Errorf("IP-literal DoH URL %q not usable without bootstrap", ipURL)
		}
	}

	bootstrap := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	c, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary, BootstrapResolution: bootstrap})
	if !ok {
		t.Fatal("arbitrary provider with bootstrap not ok")
	}
	c2, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary, BootstrapResolution: bootstrap})
	if !ok || c != c2 {
		t.Fatal("bootstrap client not cached")
	}
	// A changed bootstrap must produce a distinct client, not reuse the one
	// pinned to the old IPs.
	c3, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{
		Addr:                arbitrary,
		BootstrapResolution: []netip.Addr{netip.MustParseAddr("10.0.0.54")},
	})
	if !ok {
		t.Fatal("no client for changed bootstrap")
	}
	if c3 == c {
		t.Errorf("changed bootstrap reused the client pinned to the old IPs")
	}
}

// TestSendArbitraryDoHWithBootstrap verifies that send() dispatches an
// arbitrary (non-publicdns) https:// resolver with a bootstrap resolution
// through the DoH transport, as used for upstreams recovered from the OS's
// base DNS configuration.
func TestSendArbitraryDoHWithBootstrap(t *testing.T) {
	var gotRequests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != httpm.POST {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != dohType {
			t.Errorf("query Content-Type = %q; want %q", ct, dohType)
		}
		gotRequests.Add(1)
		w.Header().Set("Content-Type", dohType)
		w.Write(body)
	}))
	defer srv.Close()

	urlBase := srv.URL + "/dns-query"
	if ips := publicdns.DoHIPsOfBase(urlBase); len(ips) > 0 {
		t.Fatalf("%q unexpectedly a known provider", urlBase)
	}

	logf := tstest.WhileTestRunningLogger(t)
	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatal(err)
	}
	var dialer tsdial.Dialer
	dialer.SetNetMon(netMon)
	dialer.SetBus(bus)
	fwd := newForwarder(logf, netMon, nil, &dialer, health.NewTracker(bus), nil)

	bootstrap := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	r := &dnstype.Resolver{Addr: urlBase, BootstrapResolution: bootstrap}

	// A URL with a *hostname* host still requires a bootstrap resolution:
	// send would refuse it rather than silently fall back.
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: "https://doh.corp.example/query"}); ok {
		t.Fatal("client built for hostname URL without bootstrap resolution")
	}

	// Inject the test server's client at the cache key send() computes for
	// this resolver; the httptest client accepts the local certificate.
	fwd.mu.Lock()
	fwd.dohClient = map[string]*http.Client{
		dohClientCacheKey(urlBase, bootstrap): srv.Client(),
	}
	fwd.mu.Unlock()

	fq := &forwardQuery{txid: someDNSID, packet: someDNSQuestion(t), family: "udp"}
	res, err := fwd.send(context.Background(), fq, resolverAndDelay{name: r})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !bytes.Equal(res, fq.packet) {
		t.Errorf("response = %x; want echoed query", res)
	}
	if got := gotRequests.Load(); got != 1 {
		t.Errorf("saw %d requests; want 1", got)
	}
}
