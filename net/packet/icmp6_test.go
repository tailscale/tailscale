// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/types/ipproto"
)

func TestICMPv6PingResponse(t *testing.T) {
	pingHdr := ICMP6Header{
		IP6Header: IP6Header{
			Src:     netip.MustParseAddr("1::1"),
			Dst:     netip.MustParseAddr("2::2"),
			IPProto: ipproto.ICMPv6,
		},
		Type: ICMP6EchoRequest,
		Code: ICMP6NoCode,
	}

	// echoReqLen is 2 bytes identifier + 2 bytes seq number.
	// https://datatracker.ietf.org/doc/html/rfc4443#section-4.1
	// Packet.IsEchoRequest verifies that these 4 bytes are present.
	const echoReqLen = 4
	buf := make([]byte, pingHdr.Len()+echoReqLen)
	if err := pingHdr.Marshal(buf); err != nil {
		t.Fatal(err)
	}

	var p Parsed
	p.Decode(buf)
	if !p.IsEchoRequest() {
		t.Fatalf("not an echo request, got: %+v", p)
	}

	pingHdr.ToResponse()
	buf = make([]byte, pingHdr.Len()+echoReqLen)
	if err := pingHdr.Marshal(buf); err != nil {
		t.Fatal(err)
	}

	p.Decode(buf)
	if p.IsEchoRequest() {
		t.Fatalf("unexpectedly still an echo request: %+v", p)
	}
	if !p.IsEchoResponse() {
		t.Fatalf("not an echo response: %+v", p)
	}
}

func TestICMPv6Checksum(t *testing.T) {
	const req = "\x60\x0f\x07\x00\x00\x10\x3a\x40\xfd\x7a\x11\x5c\xa1\xe0\xab\x12" +
		"\x48\x43\xcd\x96\x62\x7b\x65\x28\x26\x07\xf8\xb0\x40\x0a\x08\x07" +
		"\x00\x00\x00\x00\x00\x00\x20\x0e\x80\x00\x4a\x9a\x2e\xea\x00\x02" +
		"\x61\xb1\x9e\xad\x00\x06\x45\xaa"
	// The packet that we'd originally generated incorrectly, but with the checksum
	// bytes fixed per Wireshark's correct calculation:
	const wantRes = "\x60\x00\xf8\xff\x00\x10\x3a\x40\x26\x07\xf8\xb0\x40\x0a\x08\x07" +
		"\x00\x00\x00\x00\x00\x00\x20\x0e\xfd\x7a\x11\x5c\xa1\xe0\xab\x12" +
		"\x48\x43\xcd\x96\x62\x7b\x65\x28\x81\x00\x49\x9a\x2e\xea\x00\x02" +
		"\x61\xb1\x9e\xad\x00\x06\x45\xaa"

	var p Parsed
	p.Decode([]byte(req))
	if !p.IsEchoRequest() {
		t.Fatalf("not an echo request, got: %+v", p)
	}

	h := p.ICMP6Header()
	h.ToResponse()
	pong := Generate(&h, p.Payload())

	if string(pong) != wantRes {
		t.Errorf("wrong packet\n\n got: %x\nwant: %x", pong, wantRes)
	}
}

// TestICMPv6ChecksumOddLength verifies that a checksum written by
// WriteChecksum validates for even and odd ICMPv6 payload lengths: the
// IPv6 pseudo-header and the ICMPv6 message, checksum included, must sum
// to zero. RFC 1071 pads a final odd byte with a zero low-order byte.
func TestICMPv6ChecksumOddLength(t *testing.T) {
	for _, payloadLen := range []int{0, 1, 2, 3, 4, 5, 7, 64, 65} {
		t.Run(fmt.Sprint(payloadLen), func(t *testing.T) {
			h := ICMP6Header{
				IP6Header: IP6Header{
					Src:     netip.MustParseAddr("fd7a:115c:a1e0::1"),
					Dst:     netip.MustParseAddr("2607:f8b0:400a::1"),
					IPProto: ipproto.ICMPv6,
				},
				Type: ICMP6EchoReply,
				Code: ICMP6NoCode,
			}
			buf := make([]byte, h.Len()+payloadLen)
			if err := h.Marshal(buf); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < payloadLen; i++ {
				buf[h.Len()+i] = byte(i*37 + 1)
			}
			h.WriteChecksum(buf)

			// Independently re-sum the pseudo-header and the full
			// ICMPv6 message. A valid checksum sums to zero.
			var sum uint32
			add := func(b []byte) {
				for len(b) > 1 {
					sum += uint32(binary.BigEndian.Uint16(b))
					b = b[2:]
				}
				if len(b) == 1 {
					sum += uint32(b[0]) << 8
				}
			}
			src := h.Src.As16()
			dst := h.Dst.As16()
			add(src[:])
			add(dst[:])
			var lenField [4]byte
			binary.BigEndian.PutUint32(lenField[:], uint32(len(buf)-ip6HeaderLength))
			add(lenField[:])
			add([]byte{0, 0, 0, uint8(ipproto.ICMPv6)})
			add(buf[ip6HeaderLength:])
			for sum>>16 != 0 {
				sum = (sum & 0xffff) + sum>>16
			}
			if uint16(sum) != 0xffff {
				t.Errorf("checksum does not verify: sum = %#x, want 0xffff", uint16(sum))
			}
		})
	}
}
