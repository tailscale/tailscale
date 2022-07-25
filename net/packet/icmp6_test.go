// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/types/ipproto"
)

func TestICMPv6PingResponse(t *testing.T) {
	pingHdr := ICMP6Header{
		IP6Header: IP6Header{
			Src:     netaddr.MustParseIP("1::1"),
			Dst:     netaddr.MustParseIP("2::2"),
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
	// bytes fixed per WireShark's correct calculation:
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
