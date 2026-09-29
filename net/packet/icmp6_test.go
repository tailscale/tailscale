// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
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

// refChecksum is a straightforward RFC 1071 ones' complement sum of b,
// padding an odd-length b with a trailing zero byte.
func refChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestICMPv6ChecksumOddPayload(t *testing.T) {
	src := netip.MustParseAddr("1::1")
	dst := netip.MustParseAddr("2::2")
	for _, payloadLen := range []int{0, 1, 2, 3, 4, 5, 63, 64, 65} {
		hdr := ICMP6Header{
			IP6Header: IP6Header{Src: src, Dst: dst},
			Type:      ICMP6EchoRequest,
		}
		buf := make([]byte, hdr.Len()+payloadLen)
		if err := hdr.Marshal(buf); err != nil {
			t.Fatal(err)
		}
		for i := hdr.Len(); i < len(buf); i++ {
			buf[i] = byte(0x80 + i)
		}
		hdr.WriteChecksum(buf)

		// Build the pseudo-header plus ICMPv6 message and verify that the
		// checksum written into it makes the whole sum come out to zero.
		s, d := src.As16(), dst.As16()
		pseudo := append([]byte{}, s[:]...)
		pseudo = append(pseudo, d[:]...)
		n := len(buf) - ip6HeaderLength
		pseudo = append(pseudo, 0, 0, byte(n>>8), byte(n), 0, 0, 0, byte(ipproto.ICMPv6))
		pseudo = append(pseudo, buf[ip6HeaderLength:]...)
		if got := refChecksum(pseudo); got != 0 {
			t.Errorf("payload len %d: checksum does not verify, residual = %#04x", payloadLen, got)
		}
	}
}
