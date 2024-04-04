// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resolvconffile

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

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
				Nameservers: []netip.Addr{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver 192.168.0.100 # comment`,
			want: &Config{
				Nameservers: []netip.Addr{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver 192.168.0.100#`,
			want: &Config{
				Nameservers: []netip.Addr{
					netip.MustParseAddr("192.168.0.100"),
				},
			},
		},
		{in: `nameserver #192.168.0.100`, wantErr: true},
		{in: `nameserver`, wantErr: true},
		{in: `# nameserver 192.168.0.100`, want: &Config{}},
		{in: `nameserver192.168.0.100`, wantErr: true},

		{in: `search tailscale.com`,
			want: &Config{
				SearchDomains: []dnsname.FQDN{"tailscale.com."},
			},
		},
		{in: `search tailscale.com # comment`,
			want: &Config{
				SearchDomains: []dnsname.FQDN{"tailscale.com."},
			},
		},
		{in: `searchtailscale.com`, wantErr: true},
		{in: `search`, wantErr: true},

		// Issue 6875: there can be multiple search domains, and even if they're
		// over 253 bytes long total.
		{
			in: "search search-01.example search-02.example search-03.example search-04.example search-05.example search-06.example search-07.example search-08.example search-09.example search-10.example search-11.example search-12.example search-13.example search-14.example search-15.example\n",
			want: &Config{
				SearchDomains: []dnsname.FQDN{
					"search-01.example.",
					"search-02.example.",
					"search-03.example.",
					"search-04.example.",
					"search-05.example.",
					"search-06.example.",
					"search-07.example.",
					"search-08.example.",
					"search-09.example.",
					"search-10.example.",
					"search-11.example.",
					"search-12.example.",
					"search-13.example.",
					"search-14.example.",
					"search-15.example.",
				},
			},
		},
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
