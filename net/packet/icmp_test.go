// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"bytes"
	"net/netip"
	"testing"

	"tailscale.com/types/ipproto"
)

func TestGenerateICMPHostUnreachable(t *testing.T) {
	const (
		clientPort = 1234
		serverPort = 80
	)

	makeInvokingPacket := func(src, dst netip.Addr, payloadLen int) *Parsed {
		udpPayload := bytes.Repeat([]byte("x"), payloadLen)
		var invoking []byte
		if dst.Is6() {
			invoking = Generate(UDP6Header{
				IP6Header: IP6Header{Src: src, Dst: dst},
				SrcPort:   clientPort,
				DstPort:   serverPort,
			}, udpPayload)
		} else {
			invoking = Generate(UDP4Header{
				IP4Header: IP4Header{Src: src, Dst: dst},
				SrcPort:   clientPort,
				DstPort:   serverPort,
			}, udpPayload)
		}
		var invokingPacket Parsed
		invokingPacket.Decode(invoking)
		return &invokingPacket
	}

	maxEmbeddedV4Length := 28 // IP header (20) + 64 bits (8) of original data datagram
	// As much of the packet as fits in min IPv6 MTU, which is
	// 1280 - 40 (IPv6 header) - 4 (ICMPv6 header) - 4 (unused).
	maxEmbeddedV6Length := minIPv6MTU - 40 - 4 - 4

	tests := []struct {
		name           string
		invokingPacket *Parsed
		wantProto      ipproto.Proto
		wantType       uint8
		wantCode       uint8
		fitsWhole      bool
	}{
		{
			name: "ipv4-fits-whole",
			invokingPacket: makeInvokingPacket(
				netip.MustParseAddr("100.70.0.1"),
				netip.MustParseAddr("10.64.0.2"),
				0,
			),
			wantProto: ipproto.ICMPv4,
			wantType:  uint8(ICMP4Unreachable),
			wantCode:  uint8(ICMP4HostUnreachable),
			fitsWhole: true,
		},
		{
			name: "ipv4-truncated-to-ip-header-plus-8",
			invokingPacket: makeInvokingPacket(
				netip.MustParseAddr("100.70.0.1"),
				netip.MustParseAddr("10.64.0.2"),
				100,
			),
			wantProto: ipproto.ICMPv4,
			wantType:  uint8(ICMP4Unreachable),
			wantCode:  uint8(ICMP4HostUnreachable),
		},
		{
			name: "ipv6-fits-whole",
			invokingPacket: makeInvokingPacket(
				netip.MustParseAddr("fd7a:115c:a1e0::1"),
				netip.MustParseAddr("fd7a:115c:a1e0::2"),
				5,
			),
			wantProto: ipproto.ICMPv6,
			wantType:  uint8(ICMP6Unreachable),
			wantCode:  uint8(ICMP6AddressUnreachable),
			fitsWhole: true,
		},
		{
			name: "ipv6-truncated-to-min-mtu",
			invokingPacket: makeInvokingPacket(
				netip.MustParseAddr("fd7a:115c:a1e0::1"),
				netip.MustParseAddr("fd7a:115c:a1e0::2"),
				minIPv6MTU*2,
			),
			wantProto: ipproto.ICMPv6,
			wantType:  uint8(ICMP6Unreachable),
			wantCode:  uint8(ICMP6AddressUnreachable),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iDst := tt.invokingPacket.Dst.Addr()
			iSrc := tt.invokingPacket.Src.Addr()
			// Error message's src is invoking dst and vice-versa.
			raw := GenerateICMPHostUnreachable(iDst, iSrc, tt.invokingPacket)
			if raw == nil {
				t.Fatal("GenerateICMPHostUnreachable returned nil")
			}

			var p Parsed
			p.Decode(raw)

			if !p.IsError() {
				t.Fatal("wanted an ICMP error")
			}
			if got := p.IPProto; got != tt.wantProto {
				t.Errorf("proto: got %v, want %v", got, tt.wantProto)
			}
			if want, got := iDst, p.Src.Addr(); want != got {
				t.Errorf("src: got %v, want %v", got, want)
			}
			if want, got := iSrc, p.Dst.Addr(); want != got {
				t.Errorf("dst: got %v, want %v", got, want)
			}
			var gotType, gotCode uint8
			if iDst.Is6() {
				h := p.ICMP6Header()
				gotType, gotCode = uint8(h.Type), uint8(h.Code)
			} else {
				h := p.ICMP4Header()
				gotType, gotCode = uint8(h.Type), uint8(h.Code)
			}
			if gotType != tt.wantType || gotCode != tt.wantCode {
				t.Errorf("type/code: got %d/%d, want %d/%d", gotType, gotCode, tt.wantType, tt.wantCode)
			}

			// The ICMP body must be a 4-byte zeroed "unused" field followed by
			// the embedded invoking packet.
			body := p.Payload()
			if len(body) < icmpDestUnreachableUnusedLen {
				t.Fatalf("ICMP body too short: %d bytes", len(body))
			}
			if unused := body[:icmpDestUnreachableUnusedLen]; !bytes.Equal(unused, make([]byte, icmpDestUnreachableUnusedLen)) {
				t.Errorf("unused field: got % x, want all zero", unused)
			}
			embedded := body[icmpDestUnreachableUnusedLen:]
			if !bytes.HasPrefix(tt.invokingPacket.b, embedded) {
				t.Errorf("embedded packet is not a prefix of the invoking packet:\n embedded=% x\n orig=% x", embedded, tt.invokingPacket.b[:min(len(tt.invokingPacket.b), len(embedded))])
			}
			if !tt.fitsWhole {
				// embedded should be truncated to the max
				wantLen := maxEmbeddedV4Length
				if iSrc.Is6() {
					wantLen = maxEmbeddedV6Length
				}
				if len(embedded) != wantLen {
					t.Errorf("embedded length: got %d, want %d (orig %d)", len(embedded), wantLen, len(tt.invokingPacket.b))
				}
			} else {
				// should decode to the invoking packet
				var orig Parsed
				orig.Decode(embedded)
				if got := orig.IPProto; got != ipproto.UDP {
					t.Errorf("embedded proto: got %v, want UDP", got)
				}
				if want, got := netip.AddrPortFrom(iSrc, clientPort), orig.Src; want != got {
					t.Errorf("embedded src: got %v, want %v", got, want)
				}
				if want, got := netip.AddrPortFrom(iDst, serverPort), orig.Dst; want != got {
					t.Errorf("embedded dst: got %v, want %v", got, want)
				}
			}
		})
	}
}

func TestGenerateICMPHostUnreachableMixedFamily(t *testing.T) {
	v4 := netip.MustParseAddr("100.70.0.1")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::1")

	var empty Parsed
	if got := GenerateICMPHostUnreachable(v4, v6, &empty); got != nil {
		t.Errorf("mixed family: got % x, want nil", got)
	}
	if got := GenerateICMPHostUnreachable(netip.Addr{}, v4, &empty); got != nil {
		t.Errorf("invalid from: got % x, want nil", got)
	}
}
