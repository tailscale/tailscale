// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

func TestConfigClone(t *testing.T) {
	tests := []struct {
		name string
		conf *Config
	}{
		{
			name: "nil",
			conf: nil,
		},
		{
			name: "empty",
			conf: &Config{},
		},
		{
			name: "full",
			conf: &Config{
				DefaultResolvers: []*dnstype.Resolver{
					{
						Addr:                "abc",
						BootstrapResolution: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
						UseWithExitNode:     true,
					},
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					"foo.bar.": {
						{
							Addr:                "abc",
							BootstrapResolution: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
							UseWithExitNode:     true,
						},
					},
				},
				SearchDomains: []dnsname.FQDN{"bar.baz."},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"host.bar.": {netip.MustParseAddr("5.6.7.8")},
				},
				OnlyIPv6: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.conf.Clone()
			if !reflect.DeepEqual(got, tt.conf) {
				t.Error("Cloned result is not reflect.DeepEqual")
			}
			if !got.Equal(tt.conf) {
				t.Error("Cloned result is not Equal")
			}
		})
	}
}
