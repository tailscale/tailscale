// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/types/preftype"
)

func mustCIDRs(ss ...string) []netaddr.IPPrefix {
	var ret []netaddr.IPPrefix
	for _, s := range ss {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return ret
}

func TestConfigEqual(t *testing.T) {
	testedFields := []string{
		"LocalAddrs", "Routes", "LocalRoutes", "SubnetRoutes",
		"SNATSubnetRoutes", "NetfilterMode",
	}
	configType := reflect.TypeOf(Config{})
	configFields := []string{}
	for i := 0; i < configType.NumField(); i++ {
		configFields = append(configFields, configType.Field(i).Name)
	}
	if !reflect.DeepEqual(configFields, testedFields) {
		t.Errorf("Config.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			configFields, testedFields)
	}

	nets := func(strs ...string) (ns []netaddr.IPPrefix) {
		for _, s := range strs {
			n, err := netip.ParsePrefix(s)
			if err != nil {
				panic(err)
			}
			ns = append(ns, n)
		}
		return ns
	}
	tests := []struct {
		a, b *Config
		want bool
	}{
		{
			nil,
			nil,
			true,
		},
		{
			&Config{},
			nil,
			false,
		},
		{
			nil,
			&Config{},
			false,
		},
		{
			&Config{},
			&Config{},
			true,
		},

		{
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			&Config{LocalAddrs: nets("100.2.19.82/32")},
			false,
		},
		{
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			&Config{LocalAddrs: nets("100.1.27.82/32")},
			true,
		},

		{
			&Config{Routes: nets("100.1.27.0/24")},
			&Config{Routes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{Routes: nets("100.2.19.0/24")},
			&Config{Routes: nets("100.2.19.0/24")},
			true,
		},

		{
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			&Config{LocalRoutes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			&Config{LocalRoutes: nets("100.1.27.0/24")},
			true,
		},

		{
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			&Config{SubnetRoutes: nets("100.2.19.0/24")},
			false,
		},
		{
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			&Config{SubnetRoutes: nets("100.1.27.0/24")},
			true,
		},

		{
			&Config{SNATSubnetRoutes: false},
			&Config{SNATSubnetRoutes: true},
			false,
		},
		{
			&Config{SNATSubnetRoutes: false},
			&Config{SNATSubnetRoutes: false},
			true,
		},

		{
			&Config{NetfilterMode: preftype.NetfilterOff},
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			false,
		},
		{
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			&Config{NetfilterMode: preftype.NetfilterNoDivert},
			true,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}
