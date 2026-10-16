// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package via64

import (
	"net/netip"
	"testing"

	"tailscale.com/types/ipproto"
)

func TestKernelHandled(t *testing.T) {
	t.Cleanup(func() { SetKernelHandled(nil, true) })
	in := netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1790:a63:2")
	out := netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:7:a63:2")

	if KernelHandles(in, ipproto.TCP) {
		t.Fatal("KernelHandles is true before any prefixes were set")
	}
	SetKernelHandled([]netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}, true)
	if !KernelHandles(in, ipproto.TCP) {
		t.Errorf("KernelHandles(%v, TCP) = false; want true", in)
	}
	if KernelHandles(out, ipproto.TCP) {
		t.Errorf("KernelHandles(%v, TCP) = true; want false", out)
	}
	SetKernelHandled(nil, true)
	if KernelHandles(in, ipproto.TCP) {
		t.Error("still kernel-handled after SetKernelHandled(nil)")
	}
}

func TestKernelHandlesLeavesHostTargets(t *testing.T) {
	t.Cleanup(func() { SetKernelHandled(nil, true); SetHostInterfaces(nil) })
	SetKernelHandled([]netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}, true)
	SetHostInterfaces(map[string][]netip.Prefix{
		"enp2s0":          {netip.MustParsePrefix("10.1.0.147/22"), netip.MustParsePrefix("2601::1/64")},
		"docker0":         {netip.MustParsePrefix("172.17.0.1/16")},
		"br-0123456789ab": {netip.MustParsePrefix("172.18.0.1/16")},    // a user-defined Docker network
		"br-lan":          {netip.MustParsePrefix("192.168.1.1/24")},   // an ordinary bridge
		"virbr0":          {netip.MustParsePrefix("192.168.122.1/24")}, // a libvirt NAT network
		"virbr-lan":       {netip.MustParsePrefix("192.168.7.1/24")},   // not libvirt's naming
	})
	for _, tc := range []struct {
		via  string
		want bool
	}{
		{"fd7a:115c:a1e0:b1a:0:1790:a01:ae", true},  // 10.1.0.174, a LAN host: the kernel forwards it
		{"fd7a:115c:a1e0:b1a:0:1790:a01:93", false}, // 10.1.0.147, this router: netstack delivers it locally, past any INPUT policy
		{"fd7a:115c:a1e0:b1a:0:1790:7f00:1", false}, // 127.0.0.1 (TS_4VIA6_ALLOW_LOCAL): the kernel would drop it as a martian
		// Non-unicast targets, which TS_4VIA6_ALLOW_LOCAL can permit.
		{"fd7a:115c:a1e0:b1a:0:1790:e000:1", false},    // 224.0.0.1
		{"fd7a:115c:a1e0:b1a:0:1790:ffff:ffff", false}, // 255.255.255.255
		{"fd7a:115c:a1e0:b1a:0:1790:0:0", false},       // 0.0.0.0
		{"fd7a:115c:a1e0:b1a:0:1790:a9fe:101", false},  // 169.254.1.1
		// Containers on this host's Docker networks.
		{"fd7a:115c:a1e0:b1a:0:1790:ac11:5", false},  // 172.17.0.5
		{"fd7a:115c:a1e0:b1a:0:1790:ac12:9", false},  // 172.18.0.9
		{"fd7a:115c:a1e0:b1a:0:1790:c0a8:132", true}, // 192.168.1.50, behind an ordinary bridge
		// A VM on a libvirt NAT network.
		{"fd7a:115c:a1e0:b1a:0:1790:c0a8:7a0a", false}, // 192.168.122.10
		{"fd7a:115c:a1e0:b1a:0:1790:c0a8:70a", true},   // 192.168.7.10
	} {
		if got := KernelHandles(netip.MustParseAddr(tc.via), ipproto.TCP); got != tc.want {
			t.Errorf("KernelHandles(%s, TCP) = %v; want %v", tc.via, got, tc.want)
		}
	}
}

// TestKernelHandlesProtocols checks that only what the translator handles goes to the kernel, and UDP only with udp set.
func TestKernelHandlesProtocols(t *testing.T) {
	t.Cleanup(func() { SetKernelHandled(nil, true) })
	ip := netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1790:a01:ae")
	for _, udp := range []bool{true, false} {
		SetKernelHandled([]netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}, udp)
		for proto, want := range map[ipproto.Proto]bool{ipproto.TCP: true, ipproto.ICMPv6: true, ipproto.UDP: udp, ipproto.Fragment: udp, ipproto.SCTP: false, ipproto.Proto(47): false, ipproto.ICMPv4: false} {
			if got := KernelHandles(ip, proto); got != want {
				t.Errorf("udp %v: KernelHandles(%v) = %v; want %v", udp, proto, got, want)
			}
		}
	}
}
