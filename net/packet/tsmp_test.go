// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"net/netip"
	"testing"
)

func TestTailscaleRejectedHeader(t *testing.T) {
	tests := []struct {
		h       TailscaleRejectedHeader
		wantStr string
	}{
		{
			h: TailscaleRejectedHeader{
				IPSrc:  netip.MustParseAddr("5.5.5.5"),
				IPDst:  netip.MustParseAddr("1.2.3.4"),
				Src:    netip.MustParseAddrPort("1.2.3.4:567"),
				Dst:    netip.MustParseAddrPort("5.5.5.5:443"),
				Proto:  TCP,
				Reason: RejectedDueToACLs,
			},
			wantStr: "TSMP-reject-flow{TCP 1.2.3.4:567 > 5.5.5.5:443}: acl",
		},
		{
			h: TailscaleRejectedHeader{
				IPSrc:  netip.MustParseAddr("2::2"),
				IPDst:  netip.MustParseAddr("1::1"),
				Src:    netip.MustParseAddrPort("[1::1]:567"),
				Dst:    netip.MustParseAddrPort("[2::2]:443"),
				Proto:  UDP,
				Reason: RejectedDueToShieldsUp,
			},
			wantStr: "TSMP-reject-flow{UDP [1::1]:567 > [2::2]:443}: shields",
		},
		{
			h: TailscaleRejectedHeader{
				IPSrc:       netip.MustParseAddr("2::2"),
				IPDst:       netip.MustParseAddr("1::1"),
				Src:         netip.MustParseAddrPort("[1::1]:567"),
				Dst:         netip.MustParseAddrPort("[2::2]:443"),
				Proto:       UDP,
				Reason:      RejectedDueToIPForwarding,
				MaybeBroken: true,
			},
			wantStr: "TSMP-reject-flow{UDP [1::1]:567 > [2::2]:443}: host-ip-forwarding-unavailable",
		},
	}
	for i, tt := range tests {
		gotStr := tt.h.String()
		if gotStr != tt.wantStr {
			t.Errorf("%v. String = %q; want %q", i, gotStr, tt.wantStr)
			continue
		}
		pkt := make([]byte, tt.h.Len())
		tt.h.Marshal(pkt)

		var p Parsed
		p.Decode(pkt)
		t.Logf("Parsed: %+v", p)
		t.Logf("Parsed: %s", p.String())
		back, ok := p.AsTailscaleRejectedHeader()
		if !ok {
			t.Errorf("%v. %q (%02x) didn't parse back", i, gotStr, pkt)
			continue
		}
		if back != tt.h {
			t.Errorf("%v. %q parsed back as %q", i, tt.h, back)
		}
	}
}

func TestTSMPDiscoKeyRequest(t *testing.T) {
	t.Run("Manual", func(t *testing.T) {
		var payload [1]byte
		payload[0] = byte(TSMPTypeDiscoKeyRequest)

		var p Parsed
		p.IPProto = TSMP
		p.dataofs = 40 // simulate after IP header
		buf := make([]byte, 40+1)
		copy(buf[40:], payload[:])
		p.b = buf
		p.length = len(buf)

		_, ok := p.AsTSMPDiscoKeyRequest()
		if !ok {
			t.Fatal("failed to parse TSMP disco key request")
		}
	})

	t.Run("RoundTripIPv4", func(t *testing.T) {
		src := netip.MustParseAddr("100.64.0.1")
		dst := netip.MustParseAddr("100.64.0.2")

		iph := IP4Header{
			IPProto: TSMP,
			Src:     src,
			Dst:     dst,
		}

		var payload [1]byte
		payload[0] = byte(TSMPTypeDiscoKeyRequest)

		pkt := Generate(iph, payload[:])
		t.Logf("Generated packet: %d bytes, hex: %x", len(pkt), pkt)

		// Manually check what decode4 would see
		if len(pkt) >= 4 {
			declaredLen := int(uint16(pkt[2])<<8 | uint16(pkt[3]))
			t.Logf("Packet buffer length: %d, IP header declares length: %d", len(pkt), declaredLen)
			t.Logf("Protocol byte at [9]: 0x%02x = %d", pkt[9], pkt[9])
		}

		var p Parsed
		p.Decode(pkt)
		t.Logf("Decoded: IPVersion=%d IPProto=%v Src=%v Dst=%v length=%d dataofs=%d",
			p.IPVersion, p.IPProto, p.Src, p.Dst, p.length, p.dataofs)

		if p.IPVersion != 4 {
			t.Errorf("IPVersion = %d, want 4", p.IPVersion)
		}
		if p.IPProto != TSMP {
			t.Errorf("IPProto = %v, want TSMP", p.IPProto)
		}
		if p.Src.Addr() != src {
			t.Errorf("Src = %v, want %v", p.Src.Addr(), src)
		}
		if p.Dst.Addr() != dst {
			t.Errorf("Dst = %v, want %v", p.Dst.Addr(), dst)
		}

		_, ok := p.AsTSMPDiscoKeyRequest()
		if !ok {
			t.Fatal("failed to parse TSMP disco key request from generated packet")
		}
	})

	t.Run("RoundTripIPv6", func(t *testing.T) {
		src := netip.MustParseAddr("2001:db8::1")
		dst := netip.MustParseAddr("2001:db8::2")

		iph := IP6Header{
			IPProto: TSMP,
			Src:     src,
			Dst:     dst,
		}

		var payload [1]byte
		payload[0] = byte(TSMPTypeDiscoKeyRequest)

		pkt := Generate(iph, payload[:])
		t.Logf("Generated packet: %d bytes", len(pkt))

		var p Parsed
		p.Decode(pkt)

		if p.IPVersion != 6 {
			t.Errorf("IPVersion = %d, want 6", p.IPVersion)
		}
		if p.IPProto != TSMP {
			t.Errorf("IPProto = %v, want TSMP", p.IPProto)
		}
		if p.Src.Addr() != src {
			t.Errorf("Src = %v, want %v", p.Src.Addr(), src)
		}
		if p.Dst.Addr() != dst {
			t.Errorf("Dst = %v, want %v", p.Dst.Addr(), dst)
		}

		_, ok := p.AsTSMPDiscoKeyRequest()
		if !ok {
			t.Fatal("failed to parse TSMP disco key request from generated packet")
		}
	})
}

func TestTSMPDiscoKeyUpdate(t *testing.T) {
	var discoKey [32]byte
	for i := range discoKey {
		discoKey[i] = byte(i + 10)
	}

	t.Run("IPv4", func(t *testing.T) {
		update := TSMPDiscoKeyUpdate{
			IPHeader: IP4Header{
				IPProto: TSMP,
				Src:     netip.MustParseAddr("1.2.3.4"),
				Dst:     netip.MustParseAddr("5.6.7.8"),
			},
			DiscoKey: discoKey,
		}

		pkt := make([]byte, update.Len())
		if err := update.Marshal(pkt); err != nil {
			t.Fatal(err)
		}

		var p Parsed
		p.Decode(pkt)

		parsed, ok := p.AsTSMPDiscoKeyUpdate()
		if !ok {
			t.Fatal("failed to parse TSMP disco key update")
		}
		if parsed.DiscoKey != discoKey {
			t.Errorf("disco key mismatch: got %v, want %v", parsed.DiscoKey, discoKey)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		update := TSMPDiscoKeyUpdate{
			IPHeader: IP6Header{
				IPProto: TSMP,
				Src:     netip.MustParseAddr("2001:db8::1"),
				Dst:     netip.MustParseAddr("2001:db8::2"),
			},
			DiscoKey: discoKey,
		}

		pkt := make([]byte, update.Len())
		if err := update.Marshal(pkt); err != nil {
			t.Fatal(err)
		}

		var p Parsed
		p.Decode(pkt)

		parsed, ok := p.AsTSMPDiscoKeyUpdate()
		if !ok {
			t.Fatal("failed to parse TSMP disco key update")
		}
		if parsed.DiscoKey != discoKey {
			t.Errorf("disco key mismatch: got %v, want %v", parsed.DiscoKey, discoKey)
		}
	})
}
