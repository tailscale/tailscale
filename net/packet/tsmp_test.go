// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"testing"

	"tailscale.com/net/netaddr"
)

func TestTailscaleRejectedHeader(t *testing.T) {
	tests := []struct {
		h       TailscaleRejectedHeader
		wantStr string
	}{
		{
			h: TailscaleRejectedHeader{
				IPSrc:  netaddr.MustParseIP("5.5.5.5"),
				IPDst:  netaddr.MustParseIP("1.2.3.4"),
				Src:    netaddr.MustParseIPPort("1.2.3.4:567"),
				Dst:    netaddr.MustParseIPPort("5.5.5.5:443"),
				Proto:  TCP,
				Reason: RejectedDueToACLs,
			},
			wantStr: "TSMP-reject-flow{TCP 1.2.3.4:567 > 5.5.5.5:443}: acl",
		},
		{
			h: TailscaleRejectedHeader{
				IPSrc:  netaddr.MustParseIP("2::2"),
				IPDst:  netaddr.MustParseIP("1::1"),
				Src:    netaddr.MustParseIPPort("[1::1]:567"),
				Dst:    netaddr.MustParseIPPort("[2::2]:443"),
				Proto:  UDP,
				Reason: RejectedDueToShieldsUp,
			},
			wantStr: "TSMP-reject-flow{UDP [1::1]:567 > [2::2]:443}: shields",
		},
		{
			h: TailscaleRejectedHeader{
				IPSrc:       netaddr.MustParseIP("2::2"),
				IPDst:       netaddr.MustParseIP("1::1"),
				Src:         netaddr.MustParseIPPort("[1::1]:567"),
				Dst:         netaddr.MustParseIPPort("[2::2]:443"),
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
