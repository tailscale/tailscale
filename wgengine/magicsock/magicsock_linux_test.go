// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

func TestDecodeDiscoPacket(t *testing.T) {
	mk4 := func(proto ipproto.Proto, src, dst netip.Addr, data []byte) []byte {
		if !src.Is4() || !dst.Is4() {
			panic("not an IPv4 address")
		}
		iph := &ipv4.Header{
			Version:  ipv4.Version,
			Len:      ipv4.HeaderLen,
			TotalLen: ipv4.HeaderLen + len(data),
			TTL:      64,
			Protocol: int(proto),
			Src:      net.IP(src.AsSlice()),
			Dst:      net.IP(dst.AsSlice()),
		}
		hdr, err := iph.Marshal()
		if err != nil {
			panic(err)
		}
		return append(hdr, data...)
	}
	mk6 := func(proto ipproto.Proto, src, dst netip.Addr, data []byte) []byte {
		if !src.Is6() || !dst.Is6() {
			panic("not an IPv6 address")
		}
		// The ipv6 package doesn't have a Marshal method, so just do
		// the most basic thing and construct the header manually.
		buf := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(data))
		buf[0] = 6 << 4 // version
		binary.BigEndian.PutUint16(buf[4:6], uint16(len(data)))
		buf[6] = byte(proto)
		copy(buf[8:24], src.AsSlice())
		copy(buf[24:40], dst.AsSlice())
		return append(buf, data...)
	}

	mkUDP := func(srcPort, dstPort uint16, data []byte) []byte {
		udp := make([]byte, 8, 8+len(data))
		binary.BigEndian.PutUint16(udp[0:2], srcPort)
		binary.BigEndian.PutUint16(udp[2:4], dstPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(data)))
		return append(udp, data...)
	}
	mkUDP4 := func(src, dst netip.AddrPort, data []byte) []byte {
		return mk4(ipproto.UDP, src.Addr(), dst.Addr(), mkUDP(src.Port(), dst.Port(), data))
	}
	mkUDP6 := func(src, dst netip.AddrPort, data []byte) []byte {
		return mk6(ipproto.UDP, src.Addr(), dst.Addr(), mkUDP(src.Port(), dst.Port(), data))
	}

	ip4 := netip.MustParseAddrPort("127.0.0.10:12345")
	ip4_2 := netip.MustParseAddrPort("127.0.0.99:54321")
	ip6 := netip.MustParseAddrPort("[::1]:12345")

	testCases := []struct {
		name string
		in   []byte
		is6  bool
		want bool
	}{
		{
			name: "too_short_4",
			in:   mkUDP4(ip4, ip4_2, append([]byte(disco.Magic), 0x00, 0x00)),
			is6:  false,
			want: false,
		},
		{
			name: "too_short_6",
			in:   mkUDP6(ip6, ip6, append([]byte(disco.Magic), 0x00, 0x00)),
			is6:  true,
			want: false,
		},
		{
			name: "valid_4",
			in:   mkUDP4(ip4, ip4_2, testDiscoPacket),
			is6:  false,
			want: true,
		},
		{
			name: "valid_6",
			in:   mkUDP6(ip6, ip6, testDiscoPacket),
			is6:  true,
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var pkt packet.Parsed
			got := decodeDiscoPacket(&pkt, t.Logf, tc.in, tc.is6)
			if got != tc.want {
				t.Errorf("got %v; want %v", got, tc.want)
			}
		})
	}
}

func TestEthernetProto(t *testing.T) {
	htons := func(x uint16) int {
		// Network byte order is big-endian; write the value as
		// big-endian to a byte slice and read it back in the native
		// endian-ness. This is a no-op on a big-endian platform and a
		// byte swap on a little-endian platform.
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], x)
		return int(binary.NativeEndian.Uint16(b[:]))
	}

	if v4 := ethernetProtoIPv4(); v4 != htons(unix.ETH_P_IP) {
		t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, htons(unix.ETH_P_IP))
	}
	if v6 := ethernetProtoIPv6(); v6 != htons(unix.ETH_P_IPV6) {
		t.Errorf("ethernetProtoIPv6 = 0x%04x; want 0x%04x", v6, htons(unix.ETH_P_IPV6))
	}

	// As a way to verify that the htons function is working correctly,
	// assert that the ETH_P_IP value returned from our function matches
	// the value defined in the unix package based on whether the host is
	// big-endian (network byte order) or little-endian.
	if cpu.IsBigEndian {
		if v4 := ethernetProtoIPv4(); v4 != unix.ETH_P_IP {
			t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, unix.ETH_P_IP)
		}
	} else {
		if v4 := ethernetProtoIPv4(); v4 == unix.ETH_P_IP {
			t.Errorf("ethernetProtoIPv4 = 0x%04x; want 0x%04x", v4, htons(unix.ETH_P_IP))
		} else {
			t.Logf("ethernetProtoIPv4 = 0x%04x, correctly different from 0x%04x", v4, unix.ETH_P_IP)
		}
	}
}
