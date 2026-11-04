// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func cgnatTestInterface(name string, flags net.Flags, addresses ...string) Interface {
	addrs := make([]net.Addr, 0, len(addresses))
	for _, address := range addresses {
		p := netip.MustParsePrefix(address)
		addrs = append(addrs, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	return Interface{Interface: &net.Interface{Name: name, Flags: flags}, AltAddrs: addrs}
}

func TestLocalAddressesCGNATUnderlay(t *testing.T) {
	oldName, _ := TailscaleInterfaceName()
	oldIndex, _ := TailscaleInterfaceIndex()
	t.Cleanup(func() { tsIfProps.set(oldName, oldIndex) })
	SetTailscaleInterfaceProps("custom-tap", 42)
	up := net.FlagUp
	lan := up | net.FlagBroadcast | net.FlagMulticast
	cases := []struct {
		name  string
		iface Interface
		want  []netip.Addr
	}{
		{"wifi", cgnatTestInterface("en0", lan, "100.65.10.7/16"), []netip.Addr{netip.MustParseAddr("100.65.10.7")}},
		{"ethernet", cgnatTestInterface("eth0", lan, "100.64.10.8/24"), []netip.Addr{netip.MustParseAddr("100.64.10.8")}},
		{"bridge", cgnatTestInterface("br0", lan, "100.64.11.8/24"), []netip.Addr{netip.MustParseAddr("100.64.11.8")}},
		{"renamed-tun", cgnatTestInterface("overlay0", up|net.FlagPointToPoint, "100.100.10.1/32"), nil},
		{"wireguard", cgnatTestInterface("wg0", up, "100.100.10.1/32"), nil},
		{"utun", cgnatTestInterface("utun101", up|net.FlagPointToPoint, "100.100.10.1/32", "fd7a:115c:a1e0::1/128"), nil},
		{"registered-tap", cgnatTestInterface("custom-tap", lan, "100.100.10.1/32", "192.168.99.1/24"), nil},
		{"other-tailscale", cgnatTestInterface("tailscale0", lan, "100.100.10.1/32"), nil},
		{"tailscale-ula", cgnatTestInterface("en0", lan, "fd7a:115c:a1e0::1/128"), nil},
		{"down", cgnatTestInterface("en0", net.FlagBroadcast, "100.65.10.7/16"), nil},
		{"loopback-cgnat", cgnatTestInterface("lo0", up|net.FlagLoopback, "100.65.10.7/32"), nil},
		{"problematic-overlay", cgnatTestInterface("zt0", lan, "100.65.10.7/16"), nil},
		{"nil-interface", Interface{}, nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := localAddresses([]Interface{tt.iface})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalAddressesCGNATHandover(t *testing.T) {
	lan := net.FlagUp | net.FlagBroadcast
	for _, address := range []string{"100.65.10.7/16", "100.64.11.8/24"} {
		got, _, err := localAddresses([]Interface{
			cgnatTestInterface("en0", lan, address),
			cgnatTestInterface("utun101", net.FlagUp|net.FlagPointToPoint, "100.100.10.1/32"),
		})
		want := netip.MustParsePrefix(address).Addr()
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("handover to %s: got %v, err %v", address, got, err)
		}
	}
}

func TestLocalAddressesPreservesFallbacks(t *testing.T) {
	lan := net.FlagUp | net.FlagBroadcast
	regular, loopback, err := localAddresses([]Interface{
		cgnatTestInterface("eth0", lan, "192.168.1.5/24", "2001:db8::1/64", "2001:db8::2/64", "2001:db8::3/64", "fe80::1/64"),
		cgnatTestInterface("lo", net.FlagUp|net.FlagLoopback, "127.0.0.1/8"),
	})
	if err != nil || len(regular) != 3 || len(loopback) != 1 {
		t.Fatalf("regular=%v loopback=%v err=%v", regular, loopback, err)
	}
	regular, _, err = localAddresses([]Interface{cgnatTestInterface("eth0", lan, "169.254.1.2/16", "fd00::1/64", "fe80::1/64")})
	if err != nil || len(regular) != 2 {
		t.Fatalf("fallback=%v err=%v", regular, err)
	}
}
