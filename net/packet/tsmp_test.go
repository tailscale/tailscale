// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
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

func TestTSMPDiscoKeyAdvertisementMarshal(t *testing.T) {
	var (
		// IPv4: Ver(4)Len(5), TOS, Len(53), ID, Flags, TTL(64), Proto(99), Cksum
		headerV4, _ = hex.DecodeString("45000035000000004063705d")
		// IPv6: Ver(6)TCFlow, Len(33), NextHdr(99), HopLim(64)
		headerV6, _ = hex.DecodeString("6000000000216340")

		packetType = []byte{'a'}
		testKey    = bytes.Repeat([]byte{'a'}, 32)

		// IPs
		srcV4 = netip.MustParseAddr("1.2.3.4")
		dstV4 = netip.MustParseAddr("4.3.2.1")
		srcV6 = netip.MustParseAddr("2001:db8::1")
		dstV6 = netip.MustParseAddr("2001:db8::2")
	)

	join := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}

	tests := []struct {
		name string
		tka  TSMPDiscoKeyAdvertisement
		want []byte
	}{
		{
			name: "v4Header",
			tka: TSMPDiscoKeyAdvertisement{
				Src: srcV4,
				Dst: dstV4,
				Key: key.DiscoPublicFromRaw32(mem.B(testKey)),
			},
			want: join(headerV4, srcV4.AsSlice(), dstV4.AsSlice(), packetType, testKey),
		},
		{
			name: "v6Header",
			tka: TSMPDiscoKeyAdvertisement{
				Src: srcV6,
				Dst: dstV6,
				Key: key.DiscoPublicFromRaw32(mem.B(testKey)),
			},
			want: join(headerV6, srcV6.AsSlice(), dstV6.AsSlice(), packetType, testKey),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tka.Marshal()
			if err != nil {
				t.Errorf("error mashalling TSMPDiscoAdvertisement: %s", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("error mashalling TSMPDiscoAdvertisement, expected: \n%x, \ngot:\n%x", tt.want, got)
			}
		})
	}
}
