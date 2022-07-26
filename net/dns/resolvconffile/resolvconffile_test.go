// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolvconffile

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/util/dnsname"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    *Config
		wantErr bool
	}{
		{in: `nameserver 192.168.0.100`,
			want: &Config{
				Nameservers: []netaddr.IP{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver 192.168.0.100 # comment`,
			want: &Config{
				Nameservers: []netaddr.IP{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver 192.168.0.100#`,
			want: &Config{
				Nameservers: []netaddr.IP{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver #192.168.0.100`, wantErr: true},
		{in: `nameserver`, wantErr: true},
		{in: `# nameserver 192.168.0.100`, want: &Config{}},
		{in: `nameserver192.168.0.100`, wantErr: true},

		{in: `search tailsacle.com`,
			want: &Config{
				SearchDomains: []dnsname.FQDN{"tailsacle.com."},
			},
		},
		{in: `search tailsacle.com # typo`,
			want: &Config{
				SearchDomains: []dnsname.FQDN{"tailsacle.com."},
			},
		},
		{in: `searchtailsacle.com`, wantErr: true},
		{in: `search`, wantErr: true},
	}

	for _, tt := range tests {
		cfg, err := Parse(strings.NewReader(tt.in))
		if tt.wantErr {
			if err != nil {
				continue
			}
			t.Errorf("missing error for %q", tt.in)
			continue
		}
		if err != nil {
			t.Errorf("unexpected error for %q: %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(cfg, tt.want) {
			t.Errorf("got: %v\nwant: %v\n", cfg, tt.want)
		}
	}
}
