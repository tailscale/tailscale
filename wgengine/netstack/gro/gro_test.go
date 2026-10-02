// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package gro

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/net/packet"
)

func Test_RXChecksumOffload(t *testing.T) {
	payloadLen := 100

	tcpFields := &header.TCPFields{
		SrcPort:    1,
		DstPort:    1,
		SeqNum:     1,
		AckNum:     1,
		DataOffset: 20,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 3000,
	}
	tcp4 := make([]byte, 20+20+payloadLen)
	ipv4H := header.IPv4(tcp4)
	ipv4H.Encode(&header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		TotalLength: uint16(len(tcp4)),
	})
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	tcpH := header.TCP(tcp4[20:])
	tcpH.Encode(tcpFields)
	pseudoCsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(20+payloadLen))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))

	tcp6ExtHeader := make([]byte, 40+8+20+payloadLen)
	ipv6H := header.IPv6(tcp6ExtHeader)
	ipv6H.Encode(&header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		TransportProtocol: 60, // really next header; destination options ext header
		HopLimit:          64,
		PayloadLength:     uint16(8 + 20 + payloadLen),
	})
	tcp6ExtHeader[40] = uint8(header.TCPProtocolNumber) // next header
	tcp6ExtHeader[41] = 0                               // length of ext header in 8-octet units, exclusive of first 8 octets.
	// 42-47 options and padding
	tcpH = header.TCP(tcp6ExtHeader[48:])
	tcpH.Encode(tcpFields)
	pseudoCsum = header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(20+payloadLen))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))

	tcp4InvalidCsum := make([]byte, len(tcp4))
	copy(tcp4InvalidCsum, tcp4)
	at := 20 + 16
	tcp4InvalidCsum[at] = ^tcp4InvalidCsum[at]

	tcp4FirstFragment := make([]byte, 20+20+60)
	copy(tcp4FirstFragment, tcp4[:len(tcp4FirstFragment)])
	ipv4H = header.IPv4(tcp4FirstFragment)
	ipv4H.SetTotalLength(uint16(len(tcp4FirstFragment)))
	ipv4H.SetFlagsFragmentOffset(header.IPv4FlagMoreFragments, 0)
	ipv4H.SetChecksum(0)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())

	tcp4SecondFragment := make([]byte, 20+40)
	copy(tcp4SecondFragment, tcp4[:20])
	copy(tcp4SecondFragment[20:], tcp4[20+80:])
	ipv4H = header.IPv4(tcp4SecondFragment)
	ipv4H.SetTotalLength(uint16(len(tcp4SecondFragment)))
	ipv4H.SetFlagsFragmentOffset(0, 80)
	ipv4H.SetChecksum(0)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())

	// tcp6AtomicFragment is tcp6ExtHeader with its 8-byte extension header
	// turned into a Fragment header (offset 0, no more fragments), i.e. a
	// complete packet whose L4 checksum is still valid.
	tcp6AtomicFragment := make([]byte, len(tcp6ExtHeader))
	copy(tcp6AtomicFragment, tcp6ExtHeader)
	tcp6AtomicFragment[6] = uint8(header.IPv6FragmentExtHdrIdentifier)
	binary.BigEndian.PutUint32(tcp6AtomicFragment[44:48], 0xdeadbeef) // identification

	tcp6AtomicFragmentInvalidCsum := make([]byte, len(tcp6AtomicFragment))
	copy(tcp6AtomicFragmentInvalidCsum, tcp6AtomicFragment)
	tcp6AtomicFragmentInvalidCsum[40+8+16] = ^tcp6AtomicFragmentInvalidCsum[40+8+16]

	// The first 80 bytes of the TCP segment go in the first fragment, which
	// therefore doesn't carry enough for its L4 checksum to validate.
	const firstFragLen = 80 // multiple of 8
	tcp6FirstFragment := make([]byte, 40+8+firstFragLen)
	copy(tcp6FirstFragment, tcp6AtomicFragment[:len(tcp6FirstFragment)])
	header.IPv6(tcp6FirstFragment).SetPayloadLength(uint16(8 + firstFragLen))
	tcp6FirstFragment[43] |= 1 // M flag

	tcp6SecondFragment := make([]byte, 40+8+len(tcp6AtomicFragment[48+firstFragLen:]))
	copy(tcp6SecondFragment, tcp6AtomicFragment[:48])
	copy(tcp6SecondFragment[48:], tcp6AtomicFragment[48+firstFragLen:])
	header.IPv6(tcp6SecondFragment).SetPayloadLength(uint16(len(tcp6SecondFragment) - 40))
	binary.BigEndian.PutUint16(tcp6SecondFragment[42:44], firstFragLen/8<<3) // offset, M=0

	tcp6ExtHeaderInvalidCsum := make([]byte, len(tcp6ExtHeader))
	copy(tcp6ExtHeaderInvalidCsum, tcp6ExtHeader)
	at = 40 + 8 + 16
	tcp6ExtHeaderInvalidCsum[at] = ^tcp6ExtHeaderInvalidCsum[at]

	tests := []struct {
		name   string
		input  []byte
		wantPB bool
	}{
		{
			"tcp4 packet valid csum",
			tcp4,
			true,
		},
		{
			"tcp6 with ext header valid csum",
			tcp6ExtHeader,
			true,
		},
		{
			"tcp4 packet invalid csum",
			tcp4InvalidCsum,
			false,
		},
		{
			"tcp4 first fragment skips L4 csum",
			tcp4FirstFragment,
			true,
		},
		{
			"tcp4 second fragment skips L4 csum",
			tcp4SecondFragment,
			true,
		},
		{
			"tcp6 first fragment skips L4 csum",
			tcp6FirstFragment,
			true,
		},
		{
			"tcp6 second fragment skips L4 csum",
			tcp6SecondFragment,
			true,
		},
		{
			"tcp6 atomic fragment",
			tcp6AtomicFragment,
			true,
		},
		{
			"tcp6 atomic fragment invalid csum",
			tcp6AtomicFragmentInvalidCsum,
			false,
		},
		{
			"tcp6 with ext header invalid csum",
			tcp6ExtHeaderInvalidCsum,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packet.Parsed{}
			p.Decode(tt.input)
			got := RXChecksumOffload(p)
			if tt.wantPB != (got != nil) {
				t.Fatalf("wantPB = %v != (got != nil): %v", tt.wantPB, got != nil)
			}
			if tt.wantPB {
				gotBuf := got.ToBuffer()
				if !bytes.Equal(tt.input, gotBuf.Flatten()) {
					t.Fatal("output packet unequal to input")
				}
			}
		})
	}
}
