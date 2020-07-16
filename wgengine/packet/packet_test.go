// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestIPString(t *testing.T) {
	const str = "1.2.3.4"
	ip := NewIP(net.ParseIP(str))

	var got string
	allocs := testing.AllocsPerRun(1000, func() {
		got = ip.String()
	})

	if got != str {
		t.Errorf("got %q; want %q", got, str)
	}
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

var icmpRequestBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x27, 0xde, 0xad, 0x00, 0x00, 0x40, 0x01, 0x8c, 0x15,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// ICMP header
	0x08, 0x00, 0x7d, 0x22,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var icmpRequestDecode = ParsedPacket{
	b:       icmpRequestBuffer,
	subofs:  20,
	dataofs: 24,
	length:  len(icmpRequestBuffer),

	IPProto: ICMP,
	SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
	DstIP:   NewIP(net.ParseIP("5.6.7.8")),
	SrcPort: 0,
	DstPort: 0,
}

var icmpReplyBuffer = []byte{
	0x45, 0x00, 0x00, 0x25, 0x21, 0x52, 0x00, 0x00, 0x40, 0x01, 0x49, 0x73,
	// source ip
	0x05, 0x06, 0x07, 0x08,
	// destination ip
	0x01, 0x02, 0x03, 0x04,
	// ICMP header
	0x00, 0x00, 0xe6, 0x9e,
	// "reply_payload"
	0x72, 0x65, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var icmpReplyDecode = ParsedPacket{
	b:       icmpReplyBuffer,
	subofs:  20,
	dataofs: 24,
	length:  len(icmpReplyBuffer),

	IPProto: ICMP,
	SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
	DstIP:   NewIP(net.ParseIP("5.6.7.8")),
	SrcPort: 0,
	DstPort: 0,
}

// IPv6 Router Solicitation
var ipv6PacketBuffer = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xfb, 0x57, 0x1d, 0xea, 0x9c, 0x39, 0x8f, 0xb7,
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x85, 0x00, 0x38, 0x04, 0x00, 0x00, 0x00, 0x00,
}

var ipv6PacketDecode = ParsedPacket{
	b:       ipv6PacketBuffer,
	IPProto: IPv6,
}

// This is a malformed IPv4 packet.
// Namely, the string "tcp_payload" follows the first byte of the IPv4 header.
var unknownPacketBuffer = []byte{
	0x45, 0x74, 0x63, 0x70, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var unknownPacketDecode = ParsedPacket{
	b:       unknownPacketBuffer,
	IPProto: Unknown,
}

var tcpPacketBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x37, 0xde, 0xad, 0x00, 0x00, 0x40, 0x06, 0x49, 0x5f,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// TCP header with SYN, ACK set
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcpPacketDecode = ParsedPacket{
	b:       tcpPacketBuffer,
	subofs:  20,
	dataofs: 40,
	length:  len(tcpPacketBuffer),

	IPProto:  TCP,
	SrcIP:    NewIP(net.ParseIP("1.2.3.4")),
	DstIP:    NewIP(net.ParseIP("5.6.7.8")),
	SrcPort:  123,
	DstPort:  567,
	TCPFlags: TCPSynAck,
}

var udpRequestBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x2b, 0xde, 0xad, 0x00, 0x00, 0x40, 0x11, 0x8c, 0x01,
	// source ip
	0x01, 0x02, 0x03, 0x04,
	// destination ip
	0x05, 0x06, 0x07, 0x08,
	// UDP header
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x17, 0x72, 0x1d,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udpRequestDecode = ParsedPacket{
	b:       udpRequestBuffer,
	subofs:  20,
	dataofs: 28,
	length:  len(udpRequestBuffer),

	IPProto: UDP,
	SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
	DstIP:   NewIP(net.ParseIP("5.6.7.8")),
	SrcPort: 123,
	DstPort: 567,
}

var udpReplyBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x29, 0x21, 0x52, 0x00, 0x00, 0x40, 0x11, 0x49, 0x5f,
	// source ip
	0x05, 0x06, 0x07, 0x08,
	// destination ip
	0x01, 0x02, 0x03, 0x04,
	// UDP header
	0x02, 0x37, 0x00, 0x7b, 0x00, 0x15, 0xd3, 0x9d,
	// "reply_payload"
	0x72, 0x65, 0x70, 0x6c, 0x79, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udpReplyDecode = ParsedPacket{
	b:       udpReplyBuffer,
	subofs:  20,
	dataofs: 28,
	length:  len(udpReplyBuffer),

	IPProto: UDP,
	SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
	DstIP:   NewIP(net.ParseIP("5.6.7.8")),
	SrcPort: 567,
	DstPort: 123,
}

func TestParsedPacket(t *testing.T) {
	tests := []struct {
		name    string
		qdecode ParsedPacket
		want    string
	}{
		{"tcp", tcpPacketDecode, "TCP{1.2.3.4:123 > 5.6.7.8:567}"},
		{"icmp", icmpRequestDecode, "ICMP{1.2.3.4:0 > 5.6.7.8:0}"},
		{"unknown", unknownPacketDecode, "Unknown{???}"},
		{"ipv6", ipv6PacketDecode, "IPv6{???}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.qdecode.String()
			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}

	var sink string
	allocs := testing.AllocsPerRun(1000, func() {
		sink = tests[0].qdecode.String()
	})
	_ = sink
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want ParsedPacket
	}{
		{"icmp", icmpRequestBuffer, icmpRequestDecode},
		{"ipv6", ipv6PacketBuffer, ipv6PacketDecode},
		{"unknown", unknownPacketBuffer, unknownPacketDecode},
		{"tcp", tcpPacketBuffer, tcpPacketDecode},
		{"udp", udpRequestBuffer, udpRequestDecode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ParsedPacket
			got.Decode(tt.buf)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}

	allocs := testing.AllocsPerRun(1000, func() {
		var got ParsedPacket
		got.Decode(tests[0].buf)
	})
	if allocs != 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
}

func BenchmarkDecode(b *testing.B) {
	benches := []struct {
		name string
		buf  []byte
	}{
		{"icmp", icmpRequestBuffer},
		{"unknown", unknownPacketBuffer},
		{"tcp", tcpPacketBuffer},
	}

	for _, bench := range benches {
		b.Run(bench.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var p ParsedPacket
				p.Decode(bench.buf)
			}
		})
	}
}

func TestMarshalRequest(t *testing.T) {
	// Too small to hold our packets, but only barely.
	var small [20]byte
	var large [64]byte

	icmpHeader := icmpRequestDecode.ICMPHeader()
	udpHeader := udpRequestDecode.UDPHeader()
	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{"icmp", &icmpHeader, icmpRequestBuffer},
		{"udp", &udpHeader, udpRequestBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.header.Marshal(small[:])
			if err != errSmallBuffer {
				t.Errorf("got err: nil; want: %s", errSmallBuffer)
			}

			dataOffset := tt.header.Len()
			dataLength := copy(large[dataOffset:], []byte("request_payload"))
			end := dataOffset + dataLength
			err = tt.header.Marshal(large[:end])

			if err != nil {
				t.Errorf("got err: %s; want nil", err)
			}

			if !bytes.Equal(large[:end], tt.want) {
				t.Errorf("got %x; want %x", large[:end], tt.want)
			}
		})
	}
}

func TestMarshalResponse(t *testing.T) {
	var buf [64]byte

	icmpHeader := icmpRequestDecode.ICMPHeader()
	udpHeader := udpRequestDecode.UDPHeader()

	tests := []struct {
		name   string
		header Header
		want   []byte
	}{
		{"icmp", &icmpHeader, icmpReplyBuffer},
		{"udp", &udpHeader, udpReplyBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.header.ToResponse()

			dataOffset := tt.header.Len()
			dataLength := copy(buf[dataOffset:], []byte("reply_payload"))
			end := dataOffset + dataLength
			err := tt.header.Marshal(buf[:end])

			if err != nil {
				t.Errorf("got err: %s; want nil", err)
			}

			if !bytes.Equal(buf[:end], tt.want) {
				t.Errorf("got %x; want %x", buf[:end], tt.want)
			}
		})
	}
}
