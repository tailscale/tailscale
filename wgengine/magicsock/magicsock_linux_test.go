// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
)

func TestParseUDPPacket(t *testing.T) {
	src4 := netip.MustParseAddrPort("127.0.0.1:12345")
	dst4 := netip.MustParseAddrPort("127.0.0.2:54321")

	src6 := netip.MustParseAddrPort("[::1]:12345")
	dst6 := netip.MustParseAddrPort("[::2]:54321")

	udp4Packet := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01, // source ip
		0x7f, 0x00, 0x00, 0x02, // dest ip

		// UDP header
		0x30, 0x39, // src port
		0xd4, 0x31, // dest port
		0x00, 0x12, // length; 8 bytes header + 10 bytes payload = 18 bytes
		0x00, 0x00, // checksum; unused

		// Payload: disco magic plus 4 bytes
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x00, 0x01, 0x02, 0x03,
	}
	udp6Packet := []byte{
		// IPv6 header
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x12, // payload length
		0x11, // next header: UDP
		0x00, // hop limit; unused

		// Source IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Dest IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,

		// UDP header
		0x30, 0x39, // src port
		0xd4, 0x31, // dest port
		0x00, 0x12, // length; 8 bytes header + 10 bytes payload = 18 bytes
		0x00, 0x00, // checksum; unused

		// Payload: disco magic plus 4 bytes
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac, 0x00, 0x01, 0x02, 0x03,
	}

	// Verify that parsing the UDP packet works correctly.
	t.Run("IPv4", func(t *testing.T) {
		src, dst, payload := parseUDPPacket(udp4Packet, false)
		if src != src4 {
			t.Errorf("src = %v; want %v", src, src4)
		}
		if dst != dst4 {
			t.Errorf("dst = %v; want %v", dst, dst4)
		}
		if !bytes.HasPrefix(payload, []byte(disco.Magic)) {
			t.Errorf("payload = %x; must start with %x", payload, disco.Magic)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		src, dst, payload := parseUDPPacket(udp6Packet, true)
		if src != src6 {
			t.Errorf("src = %v; want %v", src, src6)
		}
		if dst != dst6 {
			t.Errorf("dst = %v; want %v", dst, dst6)
		}
		if !bytes.HasPrefix(payload, []byte(disco.Magic)) {
			t.Errorf("payload = %x; must start with %x", payload, disco.Magic)
		}
	})
	t.Run("Truncated", func(t *testing.T) {
		truncateBy := func(b []byte, n int) []byte {
			if n >= len(b) {
				return nil
			}
			return b[:len(b)-n]
		}

		src, dst, payload := parseUDPPacket(truncateBy(udp4Packet, 11), false)
		if payload != nil {
			t.Errorf("payload = %x; want nil", payload)
		}
		if src.IsValid() || dst.IsValid() {
			t.Errorf("src = %v, dst = %v; want invalid", src, dst)
		}

		src, dst, payload = parseUDPPacket(truncateBy(udp6Packet, 11), true)
		if payload != nil {
			t.Errorf("payload = %x; want nil", payload)
		}
		if src.IsValid() || dst.IsValid() {
			t.Errorf("src = %v, dst = %v; want invalid", src, dst)
		}
	})
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
