// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains tests and benchmarks that use types from other packages
// in the Tailscale codebase. Unlike other deephash tests, these are in the _test
// package to avoid circular dependencies.

package deephash_test

import (
	"net/netip"
	"testing"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"

	. "tailscale.com/util/deephash"
)

var sink Sum

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	v := getVal()
	for range b.N {
		sink = Hash(v)
	}
}

func BenchmarkAppendTo(b *testing.B) {
	b.ReportAllocs()
	v := getVal()
	h := Hash(v)

	hashBuf := make([]byte, 0, 100)
	b.ResetTimer()
	for range b.N {
		hashBuf = h.AppendTo(hashBuf[:0])
	}
}

func TestDeepHash(t *testing.T) {
	// v contains the types of values we care about for our current callers.
	// Mostly we're just testing that we don't panic on handled types.
	v := getVal()
	hash1 := Hash(v)
	t.Logf("hash: %v", hash1)
	for range 20 {
		v := getVal()
		hash2 := Hash(v)
		if hash1 != hash2 {
			t.Error("second hash didn't match")
		}
	}
}

func TestAppendTo(t *testing.T) {
	v := getVal()
	h := Hash(v)
	sum := h.AppendTo(nil)

	if s := h.String(); s != string(sum) {
		t.Errorf("hash sum mismatch; h.String()=%q h.AppendTo()=%q", s, string(sum))
	}
}

type tailscaleTypes struct {
	WGConfig         *wgcfg.Config
	RouterConfig     *router.Config
	MapFQDNAddrs     map[dnsname.FQDN][]netip.Addr
	MapFQDNAddrPorts map[dnsname.FQDN][]netip.AddrPort
	MapDiscoPublics  map[key.DiscoPublic]bool
	MapResponse      *tailcfg.MapResponse
	FilterMatch      filter.Match
}

func getVal() *tailscaleTypes {
	return &tailscaleTypes{
		&wgcfg.Config{
			Addresses: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16([16]byte{3: 3}).Unmap(), 5)},
			Peers: []wgcfg.Peer{
				{
					PublicKey: key.NodePublic{},
				},
			},
		},
		&router.Config{
			Routes: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("1234::/64"),
			},
		},
		map[dnsname.FQDN][]netip.Addr{
			dnsname.FQDN("a."): {netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("4.3.2.1")},
			dnsname.FQDN("b."): {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")},
			dnsname.FQDN("c."): {netip.MustParseAddr("6.6.6.6"), netip.MustParseAddr("7.7.7.7")},
			dnsname.FQDN("d."): {netip.MustParseAddr("6.7.6.6"), netip.MustParseAddr("7.7.7.8")},
			dnsname.FQDN("e."): {netip.MustParseAddr("6.8.6.6"), netip.MustParseAddr("7.7.7.9")},
			dnsname.FQDN("f."): {netip.MustParseAddr("6.9.6.6"), netip.MustParseAddr("7.7.7.0")},
		},
		map[dnsname.FQDN][]netip.AddrPort{
			dnsname.FQDN("a."): {netip.MustParseAddrPort("1.2.3.4:11"), netip.MustParseAddrPort("4.3.2.1:22")},
			dnsname.FQDN("b."): {netip.MustParseAddrPort("8.8.8.8:11"), netip.MustParseAddrPort("9.9.9.9:22")},
			dnsname.FQDN("c."): {netip.MustParseAddrPort("8.8.8.8:12"), netip.MustParseAddrPort("9.9.9.9:23")},
			dnsname.FQDN("d."): {netip.MustParseAddrPort("8.8.8.8:13"), netip.MustParseAddrPort("9.9.9.9:24")},
			dnsname.FQDN("e."): {netip.MustParseAddrPort("8.8.8.8:14"), netip.MustParseAddrPort("9.9.9.9:25")},
		},
		map[key.DiscoPublic]bool{
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 31: 0})): true,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 2, 31: 0})): false,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 3, 31: 0})): true,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 4, 31: 0})): false,
		},
		&tailcfg.MapResponse{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[int]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "foo",
						Nodes: []*tailcfg.DERPNode{
							{
								Name:     "n1",
								RegionID: 1,
								HostName: "foo.com",
							},
							{
								Name:     "n2",
								RegionID: 1,
								HostName: "bar.com",
							},
						},
					},
				},
			},
			DNSConfig: &tailcfg.DNSConfig{
				Resolvers: []*dnstype.Resolver{
					{Addr: "10.0.0.1"},
				},
			},
			PacketFilter: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"1.2.3.4"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "1.2.3.4/32",
							Ports: tailcfg.PortRange{First: 1, Last: 2},
						},
					},
				},
			},
			Peers: []*tailcfg.Node{
				{
					ID: 1,
				},
				{
					ID: 2,
				},
			},
			UserProfiles: []tailcfg.UserProfile{
				{ID: 1, LoginName: "foo@bar.com"},
				{ID: 2, LoginName: "bar@foo.com"},
			},
		},
		filter.Match{
			IPProto: views.SliceOf([]ipproto.Proto{1, 2, 3}),
		},
	}
}
