// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"encoding/json"
	"net"
	"testing"

	"inet.af/netaddr"
)

func TestGetState(t *testing.T) {
	st, err := GetState()
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.MarshalIndent(st, "", "\t")
	if err != nil {
		t.Errorf("JSON: %v", err)
	}
	t.Logf("Got: %s", j)
	t.Logf("As string: %s", st)

	st2, err := GetState()
	if err != nil {
		t.Fatal(err)
	}

	if !st.EqualFiltered(st2, UseAllInterfaces, UseAllIPs) {
		// let's assume nobody was changing the system network interfaces between
		// the two GetState calls.
		t.Fatal("two States back-to-back were not equal")
	}

	t.Logf("As string:\n\t%s", st)
}

func TestLikelyHomeRouterIP(t *testing.T) {
	gw, my, ok := LikelyHomeRouterIP()
	if !ok {
		t.Logf("no result")
		return
	}
	t.Logf("myIP = %v; gw = %v", my, gw)
}

func TestIsUsableV6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"first ULA", "fc00::1", true},
		{"Tailscale", "fd7a:115c:a1e0::1", false},
		{"Cloud Run", "fddf:3978:feb1:d745::1", true},
		{"zeros", "0000:0000:0000:0000:0000:0000:0000:0000", false},
		{"Link Local", "fe80::1", false},
		{"Global", "2602::1", true},
		{"IPv4 public", "192.0.2.1", false},
		{"IPv4 private", "192.168.1.1", false},
	}

	for _, test := range tests {
		if got := isUsableV6(netaddr.MustParseIP(test.ip)); got != test.want {
			t.Errorf("isUsableV6(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestStateEqualFilteredIPFilter(t *testing.T) {
	// s1 and s2 are identical, except that an "interesting" interface
	// has gained an "uninteresting" IP address.

	s1 := &State{
		InterfaceIPs: map[string][]netaddr.IPPrefix{"x": {
			netaddr.MustParseIPPrefix("42.0.0.0/8"),
			netaddr.MustParseIPPrefix("169.254.0.0/16"), // link local unicast
		}},
		Interface: map[string]Interface{"x": {Interface: &net.Interface{Name: "x"}}},
	}

	s2 := &State{
		InterfaceIPs: map[string][]netaddr.IPPrefix{"x": {
			netaddr.MustParseIPPrefix("42.0.0.0/8"),
			netaddr.MustParseIPPrefix("169.254.0.0/16"), // link local unicast
			netaddr.MustParseIPPrefix("127.0.0.0/8"),    // loopback (added)
		}},
		Interface: map[string]Interface{"x": {Interface: &net.Interface{Name: "x"}}},
	}

	// s1 and s2 are different...
	if s1.EqualFiltered(s2, UseAllInterfaces, UseAllIPs) {
		t.Errorf("%+v != %+v", s1, s2)
	}
	// ...and they look different if you only restrict to interesting interfaces...
	if s1.EqualFiltered(s2, UseInterestingInterfaces, UseAllIPs) {
		t.Errorf("%+v != %+v when restricting to interesting interfaces _but not_ IPs", s1, s2)
	}
	// ...but because the additional IP address is uninteresting, we should treat them as the same.
	if !s1.EqualFiltered(s2, UseInterestingInterfaces, UseInterestingIPs) {
		t.Errorf("%+v == %+v when restricting to interesting interfaces and IPs", s1, s2)
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		name string
		s    *State
		want string
	}{
		{
			name: "typical_linux",
			s: &State{
				DefaultRouteInterface: "eth0",
				Interface: map[string]Interface{
					"eth0": {
						Interface: &net.Interface{
							Flags: net.FlagUp,
						},
					},
					"wlan0": {
						Interface: &net.Interface{},
					},
				},
				InterfaceIPs: map[string][]netaddr.IPPrefix{
					"eth0": []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("10.0.0.2/8"),
					},
				},
				HaveV4: true,
			},
			want: `interfaces.State{defaultRoute=eth0 ifs={eth0:[10.0.0.2/8]} v4=true v6=false}`,
		},
		{
			name: "default_desc",
			s: &State{
				DefaultRouteInterface: "foo",
				Interface: map[string]Interface{
					"foo": {
						Desc: "a foo thing",
					},
				},
			},
			want: `interfaces.State{defaultRoute=foo (a foo thing) ifs={} v4=false v6=false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.s.String()
			if got != tt.want {
				t.Errorf("wrong\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}
