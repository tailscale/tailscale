// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/types/preftype"
)

func TestConfigEqual(t *testing.T) {
	testedFields := []string{
		"LocalAddrs", "Routes", "LocalRoutes", "NewMTU",
		"SubnetRoutes", "SNATSubnetRoutes", "StatefulFiltering",
		"NetfilterMode", "NetfilterKind",
	}
	configType := reflect.TypeFor[Config]()
	configFields := []string{}
	for i := range configType.NumField() {
		configFields = append(configFields, configType.Field(i).Name)
	}
	if !reflect.DeepEqual(configFields, testedFields) {
		t.Errorf("Config.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			configFields, testedFields)
	}

	nets := func(strs ...string) (ns []netip.Prefix) {
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
			&Config{StatefulFiltering: false},
			&Config{StatefulFiltering: true},
			false,
		},
		{
			&Config{StatefulFiltering: false},
			&Config{StatefulFiltering: false},
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
		{
			&Config{NewMTU: 0},
			&Config{NewMTU: 0},
			true,
		},
		{
			&Config{NewMTU: 1280},
			&Config{NewMTU: 0},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}
