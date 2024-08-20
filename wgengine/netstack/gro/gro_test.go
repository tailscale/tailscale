// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gro

import (
	"bytes"
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
