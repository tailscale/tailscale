// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"net"
	"testing"

	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/packet"
)

func TestParseIP(t *testing.T) {
	tests := []struct {
		host    string
		bits    int
		want    filter.Net
		wantErr string
	}{
		{"8.8.8.8", 24, filter.Net{IP: packet.NewIP(net.ParseIP("8.8.8.8")), Mask: packet.NewIP(net.ParseIP("255.255.255.0"))}, ""},
		{"8.8.8.8", 33, filter.Net{}, `invalid CIDR size 33 for host "8.8.8.8"`},
		{"8.8.8.8", -1, filter.Net{}, `invalid CIDR size -1 for host "8.8.8.8"`},
		{"0.0.0.0", 24, filter.Net{}, `ports="0.0.0.0": to allow all IP addresses, use *:port, not 0.0.0.0:port`},
		{"*", 24, filter.NetAny, ""},
		{"fe80::1", 128, filter.NetNone, `ports="fe80::1": invalid IPv4 address`},
	}
	for _, tt := range tests {
		got, err := parseIP(tt.host, tt.bits)
		if err != nil {
			if err.Error() == tt.wantErr {
				continue
			}
			t.Errorf("parseIP(%q, %v) error: %v; want error %q", tt.host, tt.bits, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseIP(%q, %v) = %#v; want %#v", tt.host, tt.bits, got, tt.want)
			continue
		}
	}
}
