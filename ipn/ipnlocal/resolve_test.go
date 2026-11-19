// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestResolveMagicDNS(t *testing.T) {
	b := newTestLocalBackend(t)

	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:       1,
			Name:     "self.tail-scale.ts.net.",
			Key:      makeNodeKeyFromID(1),
			DiscoKey: makeDiscoKeyFromID(1),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:       2,
				Name:     "peer1.tail-scale.ts.net.",
				Key:      makeNodeKeyFromID(2),
				DiscoKey: makeDiscoKeyFromID(2),
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.2/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
				},
			}).View(),
			(&tailcfg.Node{
				ID:       3,
				Name:     "v6only.tail-scale.ts.net.",
				Key:      makeNodeKeyFromID(3),
				DiscoKey: makeDiscoKeyFromID(3),
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::3/128"),
				},
			}).View(),
		},
		DNS: tailcfg.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "svc-foo.tail-scale.ts.net.", Value: "100.11.22.33"},
			},
		},
	}
	nm.Domain = "tail-scale.ts.net"
	b.currentNode().SetNetMap(nm)

	tests := []struct {
		name    string
		host    string
		network string
		wantIP  string
		wantOK  bool
	}{
		{name: "fqdn", host: "peer1.tail-scale.ts.net", network: "tcp", wantIP: "100.64.0.2", wantOK: true},
		{name: "short_name", host: "peer1", network: "tcp", wantIP: "100.64.0.2", wantOK: true},
		{name: "self_fqdn", host: "self.tail-scale.ts.net", network: "tcp", wantIP: "100.64.0.1", wantOK: true},
		{name: "self_short", host: "self", network: "tcp", wantIP: "100.64.0.1", wantOK: true},
		{name: "tcp4", host: "peer1", network: "tcp4", wantIP: "100.64.0.2", wantOK: true},
		{name: "tcp6", host: "peer1", network: "tcp6", wantIP: "fd7a:115c:a1e0::2", wantOK: true},
		{name: "v6only_tcp", host: "v6only", network: "tcp", wantIP: "fd7a:115c:a1e0::3", wantOK: true},
		{name: "v6only_tcp4_miss", host: "v6only", network: "tcp4", wantOK: false},
		{name: "extra_record", host: "svc-foo.tail-scale.ts.net", network: "tcp", wantIP: "100.11.22.33", wantOK: true},
		{name: "extra_record_tcp6_miss", host: "svc-foo.tail-scale.ts.net", network: "tcp6", wantOK: false},
		{name: "unknown", host: "nope", network: "tcp", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := b.resolveMagicDNS(tt.host, tt.network)
			if ok != tt.wantOK {
				t.Fatalf("resolveMagicDNS(%q, %q): ok=%v, want %v", tt.host, tt.network, ok, tt.wantOK)
			}
			if ok && ip.String() != tt.wantIP {
				t.Fatalf("resolveMagicDNS(%q, %q): ip=%v, want %v", tt.host, tt.network, ip, tt.wantIP)
			}
		})
	}
}

// newDualStackExtraDNSBackend returns a test backend whose netmap has
// DNS.ExtraRecords for a dual-stack Service name (A record first, AAAA
// second, as control sends them; see issue #22261) and a v6-only
// Service name.
func newDualStackExtraDNSBackend(t *testing.T) *LocalBackend {
	t.Helper()
	b := newTestLocalBackend(t)

	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:       1,
			Name:     "self.tail-scale.ts.net.",
			Key:      makeNodeKeyFromID(1),
			DiscoKey: makeDiscoKeyFromID(1),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		}).View(),
		DNS: tailcfg.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "svc-dual.tail-scale.ts.net.", Value: "100.11.22.33"},
				{Name: "svc-dual.tail-scale.ts.net.", Value: "fd7a:115c:a1e0::33"},
				{Name: "svc-v6.tail-scale.ts.net.", Value: "fd7a:115c:a1e0::44"},
			},
		},
	}
	nm.Domain = "tail-scale.ts.net"
	b.currentNode().SetNetMap(nm)
	return b
}

// TestResolveMagicDNSExtraRecordsBothFamilies verifies that a Service
// name with both an A and an AAAA DNS.ExtraRecord keeps the IPv4
// address: the AAAA record used to overwrite the A record in
// nodeBackend.extraDNS, so UserDial always got the IPv6 VIP and a
// tcp4 dial of the name failed (issue #22261).
func TestResolveMagicDNSExtraRecordsBothFamilies(t *testing.T) {
	b := newDualStackExtraDNSBackend(t)

	// Both the IPv4 and IPv6 VIPs must be retained for the name.
	addrs, ok := b.currentNode().ExtraDNSByName("svc-dual.tail-scale.ts.net")
	if !ok || len(addrs) != 2 ||
		addrs[0] != netip.MustParseAddr("100.11.22.33") ||
		addrs[1] != netip.MustParseAddr("fd7a:115c:a1e0::33") {
		t.Fatalf("ExtraDNSByName(svc-dual) = %v, %v; want [100.11.22.33 fd7a:115c:a1e0::33]", addrs, ok)
	}

	tests := []struct {
		name    string
		host    string
		network string
		wantIP  string
		wantOK  bool
	}{
		// Like device names, an unqualified network prefers IPv4.
		{name: "dual_tcp_prefers_ipv4", host: "svc-dual.tail-scale.ts.net", network: "tcp", wantIP: "100.11.22.33", wantOK: true},
		{name: "dual_tcp4", host: "svc-dual.tail-scale.ts.net", network: "tcp4", wantIP: "100.11.22.33", wantOK: true},
		{name: "dual_tcp6", host: "svc-dual.tail-scale.ts.net", network: "tcp6", wantIP: "fd7a:115c:a1e0::33", wantOK: true},
		// A v6-only Service name still resolves, and still misses for tcp4.
		{name: "v6_only_tcp", host: "svc-v6.tail-scale.ts.net", network: "tcp", wantIP: "fd7a:115c:a1e0::44", wantOK: true},
		{name: "v6_only_tcp4_miss", host: "svc-v6.tail-scale.ts.net", network: "tcp4", wantOK: false},
		{name: "v6_only_tcp6", host: "svc-v6.tail-scale.ts.net", network: "tcp6", wantIP: "fd7a:115c:a1e0::44", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := b.resolveMagicDNS(tt.host, tt.network)
			if ok != tt.wantOK {
				t.Fatalf("resolveMagicDNS(%q, %q): ok=%v, want %v", tt.host, tt.network, ok, tt.wantOK)
			}
			if ok && ip.String() != tt.wantIP {
				t.Fatalf("resolveMagicDNS(%q, %q): ip=%v, want %v", tt.host, tt.network, ip, tt.wantIP)
			}
		})
	}
}

// TestUserDialServiceNamePrefersIPv4 verifies that UserDial of a
// dual-stack Service name dials the IPv4 VIP (and that a tcp4 dial
// succeeds), matching device-name behavior (issue #22261).
func TestUserDialServiceNamePrefersIPv4(t *testing.T) {
	b := newDualStackExtraDNSBackend(t)

	got := make(chan netip.AddrPort, 1)
	b.dialer.UseNetstackForIP = func(netip.Addr) bool { return true }
	b.dialer.NetstackDialTCP = func(ctx context.Context, ipp netip.AddrPort) (net.Conn, error) {
		select {
		case got <- ipp:
		default:
		}
		c, s := net.Pipe()
		s.Close()
		return c, nil
	}
	b.dialer.NetstackDialUDP = func(context.Context, netip.AddrPort) (net.Conn, error) {
		t.Error("NetstackDialUDP should not be called for a TCP dial")
		return nil, nil
	}

	wantV4 := netip.MustParseAddrPort("100.11.22.33:50051")
	for _, network := range []string{"tcp", "tcp4"} {
		c, err := b.dialer.UserDial(context.Background(), network, "svc-dual.tail-scale.ts.net:50051")
		if err != nil {
			t.Fatalf("UserDial(%q): %v", network, err)
		}
		c.Close()
		select {
		case ipp := <-got:
			if ipp != wantV4 {
				t.Errorf("UserDial(%q) dialed %v; want %v", network, ipp, wantV4)
			}
		default:
			t.Fatalf("UserDial(%q) did not dial", network)
		}
	}
}
