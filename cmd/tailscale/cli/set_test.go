// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ptr"
)

func TestCalcAdvertiseRoutesForSet(t *testing.T) {
	pfx := netip.MustParsePrefix
	tests := []struct {
		name      string
		setExit   *bool
		setRoutes *string
		was       []netip.Prefix
		want      []netip.Prefix
	}{
		{
			name: "empty",
		},
		{
			name:    "advertise-exit",
			setExit: ptr.To(true),
			want:    tsaddr.ExitRoutes(),
		},
		{
			name:    "advertise-exit/already-routes",
			was:     []netip.Prefix{pfx("34.0.0.0/16")},
			setExit: ptr.To(true),
			want:    []netip.Prefix{pfx("34.0.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
		{
			name:    "advertise-exit/already-exit",
			was:     tsaddr.ExitRoutes(),
			setExit: ptr.To(true),
			want:    tsaddr.ExitRoutes(),
		},
		{
			name:    "stop-advertise-exit",
			was:     tsaddr.ExitRoutes(),
			setExit: ptr.To(false),
			want:    nil,
		},
		{
			name:    "stop-advertise-exit/with-routes",
			was:     []netip.Prefix{pfx("34.0.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
			setExit: ptr.To(false),
			want:    []netip.Prefix{pfx("34.0.0.0/16")},
		},
		{
			name:      "advertise-routes",
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16")},
		},
		{
			name:      "advertise-routes/already-exit",
			was:       tsaddr.ExitRoutes(),
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
		{
			name:      "advertise-routes/already-diff-routes",
			was:       []netip.Prefix{pfx("34.0.0.0/16")},
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16")},
		},
		{
			name:      "stop-advertise-routes",
			was:       []netip.Prefix{pfx("34.0.0.0/16")},
			setRoutes: ptr.To(""),
			want:      nil,
		},
		{
			name:      "stop-advertise-routes/already-exit",
			was:       []netip.Prefix{pfx("34.0.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
			setRoutes: ptr.To(""),
			want:      tsaddr.ExitRoutes(),
		},
		{
			name:      "advertise-routes-and-exit",
			setExit:   ptr.To(true),
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
		{
			name:      "advertise-routes-and-exit/already-exit",
			was:       tsaddr.ExitRoutes(),
			setExit:   ptr.To(true),
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
		{
			name:      "advertise-routes-and-exit/already-routes",
			was:       []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16")},
			setExit:   ptr.To(true),
			setRoutes: ptr.To("10.0.0.0/24,192.168.0.0/16"),
			want:      []netip.Prefix{pfx("10.0.0.0/24"), pfx("192.168.0.0/16"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			curPrefs := &ipn.Prefs{
				AdvertiseRoutes: tc.was,
			}
			sa := setArgsT{}
			if tc.setExit != nil {
				sa.advertiseDefaultRoute = *tc.setExit
			}
			if tc.setRoutes != nil {
				sa.advertiseRoutes = *tc.setRoutes
			}
			got, err := calcAdvertiseRoutesForSet(tc.setExit != nil, tc.setRoutes != nil, curPrefs, sa)
			if err != nil {
				t.Fatal(err)
			}
			tsaddr.SortPrefixes(got)
			tsaddr.SortPrefixes(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
