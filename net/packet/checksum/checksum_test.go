// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package checksum

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/net/packet"
)

func fullHeaderChecksumV4(b []byte) uint16 {
	s := uint32(0)
	for i := 0; i < len(b); i += 2 {
		if i == 10 {
			// Skip checksum field.
			continue
		}
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for s>>16 > 0 {
		s = s&0xFFFF + s>>16
	}
	return ^uint16(s)
}

func TestHeaderChecksumsV4(t *testing.T) {
	// This is not a good enough test, because it doesn't
	// check the various packet types or the many edge cases
	// of the checksum algorithm. But it's a start.

	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name: "ICMPv4",
			packet: []byte{
				0x45, 0x00, 0x00, 0x54, 0xb7, 0x96, 0x40, 0x00, 0x40, 0x01, 0x7a, 0x06, 0x64, 0x7f, 0x3f, 0x4c, 0x64, 0x40, 0x01, 0x01, 0x08, 0x00, 0x47, 0x1a, 0x00, 0x11, 0x01, 0xac, 0xcc, 0xf5, 0x95, 0x63, 0x00, 0x00, 0x00, 0x00, 0x8d, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			},
		},
		{
			name: "TLS",
			packet: []byte{
				0x45, 0x00, 0x00, 0x3c, 0x54, 0x29, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xac, 0x64, 0x42, 0xd4, 0x33, 0x64, 0x61, 0x98, 0x0f, 0xb1, 0x94, 0x01, 0xbb, 0x0a, 0x51, 0xce, 0x7c, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfb, 0xe0, 0x38, 0xf6, 0x00, 0x00, 0x02, 0x04, 0x04, 0xd8, 0x04, 0x02, 0x08, 0x0a, 0x86, 0x2b, 0xcc, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
			},
		},
		{
			name: "DNS",
			packet: []byte{
				0x45, 0x00, 0x00, 0x74, 0xe2, 0x85, 0x00, 0x00, 0x40, 0x11, 0x96, 0xb5, 0x64, 0x64, 0x64, 0x64, 0x64, 0x42, 0xd4, 0x33, 0x00, 0x35, 0xec, 0x55, 0x00, 0x60, 0xd9, 0x19, 0xed, 0xfd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x34, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x1e, 0x00, 0x0c, 0x07, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x01, 0x6c, 0xc0, 0x15, 0xc0, 0x31, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x1e, 0x00, 0x04, 0x8e, 0xfa, 0xbd, 0xce, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "DCCP",
			packet: []byte{
				0x45, 0x00, 0x00, 0x28, 0x15, 0x06, 0x40, 0x00, 0x40, 0x21, 0x5f, 0x2f, 0xc0, 0xa8, 0x01, 0x1f, 0xc9, 0x0b, 0x3b, 0xad, 0x80, 0x04, 0x13, 0x89, 0x05, 0x00, 0x08, 0xdb, 0x01, 0x00, 0x00, 0x04, 0x29, 0x01, 0x6d, 0xdc, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "SCTP",
			packet: []byte{
				0x45, 0x00, 0x00, 0x30, 0x09, 0xd9, 0x40, 0x00, 0xff, 0x84, 0x50, 0xe2, 0x0a, 0x1c, 0x06, 0x2c, 0x0a, 0x1c, 0x06, 0x2b, 0x0b, 0x80, 0x40, 0x00, 0x21, 0x44, 0x15, 0x23, 0x2b, 0xf2, 0x02, 0x4e, 0x03, 0x00, 0x00, 0x10, 0x28, 0x02, 0x43, 0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		// TODO(maisem): add test for GRE.
	}
	var p packet.Parsed
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p.Decode(tt.packet)
			t.Log(p.String())
			UpdateSrcAddr(&p, netip.MustParseAddr("100.64.0.1"))

			got := binary.BigEndian.Uint16(tt.packet[10:12])
			want := fullHeaderChecksumV4(tt.packet[:20])
			if got != want {
				t.Fatalf("got %x want %x", got, want)
			}

			UpdateDstAddr(&p, netip.MustParseAddr("100.64.0.2"))
			got = binary.BigEndian.Uint16(tt.packet[10:12])
			want = fullHeaderChecksumV4(tt.packet[:20])
			if got != want {
				t.Fatalf("got %x want %x", got, want)
			}
		})
	}
}

func TestNatChecksumsV6UDP(t *testing.T) {
	a1, a2 := randV6Addr(), randV6Addr()

	// Make a fake UDP packet with 32 bytes of zeros as the datagram payload.
	b := header.IPv6(make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize+32))
	b.Encode(&header.IPv6Fields{
		PayloadLength:     header.UDPMinimumSize + 32,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          16,
		SrcAddr:           tcpip.AddrFrom16Slice(a1.AsSlice()),
		DstAddr:           tcpip.AddrFrom16Slice(a2.AsSlice()),
	})
	udp := header.UDP(b[header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 42,
		DstPort: 43,
		Length:  header.UDPMinimumSize + 32,
	})
	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		tcpip.AddrFrom16Slice(a1.AsSlice()),
		tcpip.AddrFrom16Slice(a2.AsSlice()),
		uint16(header.UDPMinimumSize+32),
	)
	xsum = checksum.Checksum(b.Payload()[header.UDPMinimumSize:], xsum)
	udp.SetChecksum(^udp.CalculateChecksum(xsum))
	if !udp.IsChecksumValid(tcpip.AddrFrom16Slice(a1.AsSlice()), tcpip.AddrFrom16Slice(a2.AsSlice()), checksum.Checksum(b.Payload()[header.UDPMinimumSize:], 0)) {
		t.Fatal("test broken; initial packet has incorrect checksum")
	}

	// Parse the packet.
	var p, p2 packet.Parsed
	p.Decode(b)
	t.Log(p.String())

	// Update the source address of the packet to be the same as the dest.
	UpdateSrcAddr(&p, a2)
	p2.Decode(p.Buffer())
	if p2.Src.Addr() != a2 {
		t.Fatalf("got %v, want %v", p2.Src, a2)
	}
	if !udp.IsChecksumValid(tcpip.AddrFrom16Slice(a2.AsSlice()), tcpip.AddrFrom16Slice(a2.AsSlice()), checksum.Checksum(b.Payload()[header.UDPMinimumSize:], 0)) {
		t.Fatal("incorrect checksum after updating source address")
	}

	// Update the dest address of the packet to be the original source address.
	UpdateDstAddr(&p, a1)
	p2.Decode(p.Buffer())
	if p2.Dst.Addr() != a1 {
		t.Fatalf("got %v, want %v", p2.Dst, a1)
	}
	if !udp.IsChecksumValid(tcpip.AddrFrom16Slice(a2.AsSlice()), tcpip.AddrFrom16Slice(a1.AsSlice()), checksum.Checksum(b.Payload()[header.UDPMinimumSize:], 0)) {
		t.Fatal("incorrect checksum after updating destination address")
	}
}

func randV6Addr() netip.Addr {
	a1, a2 := rand.Int64(), rand.Int64()
	return netip.AddrFrom16([16]byte{
		byte(a1 >> 56), byte(a1 >> 48), byte(a1 >> 40), byte(a1 >> 32),
		byte(a1 >> 24), byte(a1 >> 16), byte(a1 >> 8), byte(a1),
		byte(a2 >> 56), byte(a2 >> 48), byte(a2 >> 40), byte(a2 >> 32),
		byte(a2 >> 24), byte(a2 >> 16), byte(a2 >> 8), byte(a2),
	})
}

func TestNatChecksumsV6TCP(t *testing.T) {
	a1, a2 := randV6Addr(), randV6Addr()

	// Make a fake TCP packet with no payload.
	b := header.IPv6(make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize))
	b.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          16,
		SrcAddr:           tcpip.AddrFrom16Slice(a1.AsSlice()),
		DstAddr:           tcpip.AddrFrom16Slice(a2.AsSlice()),
	})
	tcp := header.TCP(b[header.IPv6MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:       42,
		DstPort:       43,
		SeqNum:        1,
		AckNum:        2,
		DataOffset:    header.TCPMinimumSize,
		Flags:         3,
		WindowSize:    4,
		Checksum:      0,
		UrgentPointer: 5,
	})
	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFrom16Slice(a1.AsSlice()),
		tcpip.AddrFrom16Slice(a2.AsSlice()),
		uint16(header.TCPMinimumSize),
	)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))

	if !tcp.IsChecksumValid(tcpip.AddrFrom16Slice(a1.AsSlice()), tcpip.AddrFrom16Slice(a2.AsSlice()), 0, 0) {
		t.Fatal("test broken; initial packet has incorrect checksum")
	}

	// Parse the packet.
	var p, p2 packet.Parsed
	p.Decode(b)
	t.Log(p.String())

	// Update the source address of the packet to be the same as the dest.
	UpdateSrcAddr(&p, a2)
	p2.Decode(p.Buffer())
	if p2.Src.Addr() != a2 {
		t.Fatalf("got %v, want %v", p2.Src, a2)
	}
	if !tcp.IsChecksumValid(tcpip.AddrFrom16Slice(a2.AsSlice()), tcpip.AddrFrom16Slice(a2.AsSlice()), 0, 0) {
		t.Fatal("incorrect checksum after updating source address")
	}

	// Update the dest address of the packet to be the original source address.
	UpdateDstAddr(&p, a1)
	p2.Decode(p.Buffer())
	if p2.Dst.Addr() != a1 {
		t.Fatalf("got %v, want %v", p2.Dst, a1)
	}
	if !tcp.IsChecksumValid(tcpip.AddrFrom16Slice(a2.AsSlice()), tcpip.AddrFrom16Slice(a1.AsSlice()), 0, 0) {
		t.Fatal("incorrect checksum after updating destination address")
	}
}
