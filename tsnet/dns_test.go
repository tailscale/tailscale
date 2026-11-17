// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dnsmessage "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
)

// fakeUpstreamDNS serves UDP queries for split DNS and global resolver tests.
// It answers A and AAAA queries from addrs. Other queries return NXDOMAIN.
type fakeUpstreamDNS struct {
	t     *testing.T
	pc    net.PacketConn
	mu    sync.Mutex
	addrs map[string][]netip.Addr // lowercase names with trailing dots
}

func startFakeUpstreamDNS(t *testing.T, addrs map[string][]netip.Addr) *fakeUpstreamDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for fake upstream DNS: %v", err)
	}
	f := &fakeUpstreamDNS{t: t, pc: pc, addrs: addrs}
	t.Cleanup(func() { pc.Close() })
	go f.serve()
	return f
}

// setAnswers replaces DNS answers while the server is running.
func (f *fakeUpstreamDNS) setAnswers(addrs map[string][]netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = addrs
}

func (f *fakeUpstreamDNS) addr() string {
	return f.pc.LocalAddr().String()
}

func (f *fakeUpstreamDNS) serve() {
	for {
		buf := make([]byte, 1500)
		n, src, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		go f.respond(buf[:n], src)
	}
}

func (f *fakeUpstreamDNS) respond(query []byte, src net.Addr) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	f.mu.Lock()
	var ips []netip.Addr
	for _, ip := range f.addrs[strings.ToLower(q.Name.String())] {
		if (q.Type == dnsmessage.TypeA && ip.Is4()) || (q.Type == dnsmessage.TypeAAAA && ip.Is6()) {
			ips = append(ips, ip)
		}
	}
	f.mu.Unlock()
	rcode := dnsmessage.RCodeNameError
	if len(ips) > 0 {
		rcode = dnsmessage.RCodeSuccess
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               hdr.ID,
		Response:         true,
		RecursionDesired: hdr.RecursionDesired,
		RCode:            rcode,
	})
	if err := b.StartQuestions(); err != nil {
		return
	}
	if err := b.Question(q); err != nil {
		return
	}
	if err := b.StartAnswers(); err != nil {
		return
	}
	for _, ip := range ips {
		rh := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  q.Type,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}
		if ip.Is4() {
			var a dnsmessage.AResource
			a.A = ip.As4()
			if err := b.AResource(rh, a); err != nil {
				return
			}
		} else {
			var aaaa dnsmessage.AAAAResource
			aaaa.AAAA = ip.As16()
			if err := b.AAAAResource(rh, aaaa); err != nil {
				return
			}
		}
	}
	resp, err := b.Finish()
	if err != nil {
		return
	}
	f.pc.WriteTo(resp, src)
}

func startDNSResControl(t *testing.T, dnsCfg *tailcfg.DNSConfig) (*testcontrol.Server, string) {
	t.Helper()
	tstest.ResourceCheck(t)

	// Loopback test servers require netns to be disabled.
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      dnsCfg,
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control, control.HTTPTestServer.URL
}

func startDNSResServer(t *testing.T, controlURL, hostname string) *Server {
	t.Helper()
	s := &Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(t.Context()); err != nil {
		t.Fatalf("bringing up server %s: %v", hostname, err)
	}
	return s
}

func startDNSResTestServer(t *testing.T, dnsCfg *tailcfg.DNSConfig) *Server {
	t.Helper()
	_, controlURL := startDNSResControl(t, dnsCfg)
	return startDNSResServer(t, controlURL, "s1")
}

// TestLookupIPSearchSplitMagicDNS tests client-side search expansion,
// split DNS routing, local MagicDNS answers, and host fallback without
// global resolvers.
func TestLookupIPSearchSplitMagicDNS(t *testing.T) {
	upstream := startFakeUpstreamDNS(t, map[string][]netip.Addr{
		"db.corp.example.com.": {
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	})
	s := startDNSResTestServer(t, &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"corp.example.com"},
		Routes: map[string][]*dnstype.Resolver{
			"corp.example.com.": {{Addr: upstream.addr()}},
		},
	})
	selfIP, _ := s.TailscaleIPs()

	// Short peer names use the MagicDNS search suffix.
	ips, err := s.LookupIP(t.Context(), "ip4", "s1")
	if err != nil {
		t.Fatalf("LookupIP(s1): %v", err)
	}
	if len(ips) != 1 || ips[0] != selfIP {
		t.Errorf("LookupIP(s1) = %v; want %v", ips, selfIP)
	}

	// A short name uses the custom search domain's split DNS route.
	got, err := s.LookupIP(t.Context(), "ip", "db")
	if err != nil {
		t.Fatalf("LookupIP(db): %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	if !equalAddrs(got, want) {
		t.Errorf("LookupIP(db) = %v; want %v", got, want)
	}

	// The "ip" network returns both address families, IPv4 first.
	ips, err = s.LookupIP(t.Context(), "ip", "db")
	if err != nil {
		t.Fatalf("LookupIP(ip, db): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}; !equalAddrs(ips, want) {
		t.Errorf("LookupIP(ip, db) = %v; want %v", ips, want)
	}

	// Multi-label names are tried as absolute names first.
	got, err = s.LookupIP(t.Context(), "ip", "db.corp.example.com")
	if err != nil {
		t.Fatalf("LookupIP(db.corp.example.com): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}; !equalAddrs(got, want) {
		t.Errorf("LookupIP(db.corp.example.com) = %v; want %v", got, want)
	}

	// An authoritative denial from the split upstream is a not-found error.
	_, err = s.LookupIP(t.Context(), "ip4", "gone.corp.example.com")
	if !isNotFound(err) {
		t.Errorf("LookupIP(gone.corp.example.com) error = %v; want not-found", err)
	}

	// Names outside tailnet policy fall back to the host resolver.
	got, err = s.LookupIP(t.Context(), "ip", "localhost")
	if err != nil {
		t.Fatalf("LookupIP(localhost): %v", err)
	}
	if !slices.Contains(got, netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("LookupIP(localhost) = %v; want it to contain 127.0.0.1", got)
	}

	// UserDialPlan resolves names without connecting to the result.
	dialer := s.Sys().Dialer.Get()
	ipp, _, err := dialer.UserDialPlan(t.Context(), "tcp", "db:5432")
	if err != nil {
		t.Fatalf("UserDialPlan(db:5432): %v", err)
	}
	if want := netip.MustParseAddrPort("192.0.2.10:5432"); ipp != want {
		t.Errorf("UserDialPlan(db:5432) = %v; want %v", ipp, want)
	}
	ipp, _, err = dialer.UserDialPlan(t.Context(), "tcp", "s1:80")
	if err != nil {
		t.Fatalf("UserDialPlan(s1:80): %v", err)
	}
	if want := netip.AddrPortFrom(selfIP, 80); ipp != want {
		t.Errorf("UserDialPlan(s1:80) = %v; want %v", ipp, want)
	}

	// A trailing dot disables MagicDNS search expansion.
	_, err = s.LookupIP(t.Context(), "ip4", "s1.")
	if !isNotFound(err) {
		t.Errorf("LookupIP(s1.) error = %v; want not-found", err)
	}
}

// TestLookupIPMagicDNSDisabled verifies search expansion without a MagicDNS
// suffix and local peer-name resolution through the dialer.
func TestLookupIPMagicDNSDisabled(t *testing.T) {
	upstream := startFakeUpstreamDNS(t, nil)
	s := startDNSResTestServer(t, &tailcfg.DNSConfig{
		Proxied: false, // MagicDNS off
		Domains: []string{"corp.example.com"},
		Routes: map[string][]*dnstype.Resolver{
			"corp.example.com.": {{Addr: upstream.addr()}},
		},
	})
	upstream.setAnswers(map[string][]netip.Addr{
		"db.corp.example.com.": {netip.MustParseAddr("192.0.2.10")},
	})
	selfIP, _ := s.TailscaleIPs()

	// Custom search domains expand and route through split DNS.
	got, err := s.LookupIP(t.Context(), "ip", "db")
	if err != nil {
		t.Fatalf("LookupIP(db): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.10")}; !equalAddrs(got, want) {
		t.Errorf("LookupIP(db) = %v; want %v", got, want)
	}

	// Without a MagicDNS search suffix, LookupIP does not expand peer names.
	ips, err := s.LookupIP(t.Context(), "ip4", "s1")
	if err == nil {
		for _, ip := range ips {
			if ip == selfIP {
				t.Errorf("LookupIP(s1) = %v; the resolver must not answer the short node name when MagicDNS is off", ips)
			}
		}
	}

	// Dials resolve short node names locally even with MagicDNS disabled.
	dialer := s.Sys().Dialer.Get()
	ipp, _, err := dialer.UserDialPlan(t.Context(), "tcp", "s1:80")
	if err != nil {
		t.Fatalf("UserDialPlan(s1:80): %v", err)
	}
	if want := netip.AddrPortFrom(selfIP, 80); ipp != want {
		t.Errorf("UserDialPlan(s1:80) = %v; want %v", ipp, want)
	}
}

// TestLookupIPDialSplitDNS tests dialing a short name over the tailnet.
// A custom search domain and split DNS upstream resolve it to a peer address.
func TestLookupIPDialSplitDNS(t *testing.T) {
	upstream := startFakeUpstreamDNS(t, nil)
	_, controlURL := startDNSResControl(t, &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"corp.example.com"},
		Routes: map[string][]*dnstype.Resolver{
			"corp.example.com.": {{Addr: upstream.addr()}},
		},
	})
	s1 := startDNSResServer(t, controlURL, "s1")
	s2 := startDNSResServer(t, controlURL, "s2")
	s2ip, _ := s2.TailscaleIPs()

	// The split DNS upstream maps the service name to a tailnet peer.
	upstream.setAnswers(map[string][]netip.Addr{
		"db.corp.example.com.": {s2ip},
	})

	ln, err := s2.Listen("tcp", ":8080")
	if err != nil {
		t.Fatalf("listening on s2: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	conn, err := s1.Dial(t.Context(), "tcp", "db:8080")
	if err != nil {
		t.Fatalf("Dial(db:8080): %v", err)
	}
	defer conn.Close()
	want := "hello over split dns"
	if _, err := conn.Write([]byte(want)); err != nil {
		t.Fatalf("writing: %v", err)
	}
	buf := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(buf) != want {
		t.Errorf("echo = %q; want %q", buf, want)
	}
}

// TestLookupIPConfigChange tests DNS policy updates with a cached DNS client.
// Each lookup uses the current search domains, split routes, and MagicDNS state.
func TestLookupIPConfigChange(t *testing.T) {
	upstream := startFakeUpstreamDNS(t, map[string][]netip.Addr{
		"db.corp1.example.com.": {netip.MustParseAddr("192.0.2.10")},
		"db.corp2.example.com.": {netip.MustParseAddr("192.0.2.20")},
	})
	control, controlURL := startDNSResControl(t, &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"corp1.example.com"},
		Routes: map[string][]*dnstype.Resolver{
			"corp1.example.com.": {{Addr: upstream.addr()}},
		},
	})
	s := startDNSResServer(t, controlURL, "s1")

	got, err := s.LookupIP(t.Context(), "ip", "db")
	if err != nil {
		t.Fatalf("LookupIP(db): %v", err)
	}
	if !slices.Contains(got, netip.MustParseAddr("192.0.2.10")) {
		t.Fatalf("LookupIP(db) = %v; want 192.0.2.10", got)
	}

	// Subsequent lookups use the updated search domain and split route.
	control.SetDNSConfig(&tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"corp2.example.com"},
		Routes: map[string][]*dnstype.Resolver{
			"corp2.example.com.": {{Addr: upstream.addr()}},
		},
	})

	if err := tstest.WaitFor(30*time.Second, func() error {
		got, err := s.LookupIP(t.Context(), "ip", "db")
		if err != nil {
			return fmt.Errorf("LookupIP(db): %w", err)
		}
		if !slices.Contains(got, netip.MustParseAddr("192.0.2.20")) {
			return fmt.Errorf("LookupIP(db) = %v; still using the old config", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestLookupIPOverrideGlobal tests that "override local DNS" sends names
// without local answers to the global upstream.
func TestLookupIPOverrideGlobal(t *testing.T) {
	upstream := startFakeUpstreamDNS(t, map[string][]netip.Addr{
		"example.com.": {netip.MustParseAddr("192.0.2.20")},
		"localhost.":   {netip.MustParseAddr("192.0.2.21")},
	})
	s := startDNSResTestServer(t, &tailcfg.DNSConfig{
		Proxied:   true,
		Resolvers: []*dnstype.Resolver{{Addr: upstream.addr()}},
	})

	got, err := s.LookupIP(t.Context(), "ip", "example.com")
	if err != nil {
		t.Fatalf("LookupIP(example.com): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.20")}; !equalAddrs(got, want) {
		t.Errorf("LookupIP(example.com) = %v; want %v", got, want)
	}

	// Configured DNS answers override local host entries.
	got, err = s.LookupIP(t.Context(), "ip4", "localhost")
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.21")}; err != nil || !equalAddrs(got, want) {
		t.Fatalf("LookupIP(localhost) = %v, %v; want %v from tailnet DNS", got, err, want)
	}

	// MagicDNS answers take precedence over global upstreams.
	ips, err := s.LookupIP(t.Context(), "ip4", "s1")
	if err != nil {
		t.Fatalf("LookupIP(s1): %v", err)
	}
	selfIP, _ := s.TailscaleIPs()
	if len(ips) != 1 || ips[0] != selfIP {
		t.Errorf("LookupIP(s1) = %v; want %v", ips, selfIP)
	}

	// Configured DNS denials disable host fallback.
	upstream.setAnswers(nil)
	_, err = s.LookupIP(t.Context(), "ip4", "localhost")
	if !isNotFound(err) {
		t.Errorf("LookupIP(localhost) error = %v; want not-found", err)
	}
}

// TestLookupIPLiteral tests that IP literals bypass DNS.
func TestLookupIPLiteral(t *testing.T) {
	s := startDNSResTestServer(t, &tailcfg.DNSConfig{Proxied: true})

	got, err := s.LookupIP(t.Context(), "ip", "192.0.2.1")
	if err != nil {
		t.Fatalf("LookupIP(192.0.2.1): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}; !equalAddrs(got, want) {
		t.Errorf("LookupIP(192.0.2.1) = %v; want %v", got, want)
	}
	ips, err := s.LookupIP(t.Context(), "ip6", "2001:db8::1")
	if err != nil {
		t.Fatalf("LookupIP(ip6, 2001:db8::1): %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("2001:db8::1")}; !equalAddrs(ips, want) {
		t.Errorf("LookupIP(ip6, 2001:db8::1) = %v; want %v", ips, want)
	}
	// Wrong address family is an error.
	if _, err := s.LookupIP(t.Context(), "ip4", "2001:db8::1"); !isNotFound(err) {
		t.Errorf("LookupIP(ip4, 2001:db8::1) error = %v; want not-found", err)
	}
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func equalAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
