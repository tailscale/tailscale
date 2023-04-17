// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/tstest"
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
	ipnet := func(s string) net.Addr {
		ip, ipnet, err := net.ParseCIDR(s)
		ipnet.IP = ip
		if err != nil {
			t.Fatal(err)
		}
		return ipnet
	}

	mockInterfaces := []Interface{
		// Interface that's not running
		{
			Interface: &net.Interface{
				Index: 1,
				MTU:   1500,
				Name:  "down0",
				Flags: net.FlagBroadcast | net.FlagMulticast,
			},
			AltAddrs: []net.Addr{
				ipnet("10.0.0.100/8"),
			},
		},

		// Interface that's up, but only has an IPv6 address
		{
			Interface: &net.Interface{
				Index: 2,
				MTU:   1500,
				Name:  "ipsixonly0",
				Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
			},
			AltAddrs: []net.Addr{
				ipnet("76f9:2e7d:55dd:48e1:48d0:763a:b591:b1bc/64"),
			},
		},

		// Fake interface with a gateway to the internet
		{
			Interface: &net.Interface{
				Index: 3,
				MTU:   1500,
				Name:  "fake0",
				Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
			},
			AltAddrs: []net.Addr{
				ipnet("23a1:99c9:3a88:1d29:74d4:957b:2133:3f4e/64"),
				ipnet("192.168.7.100/24"),
			},
		},
	}

	// Mock out the responses from netInterfaces()
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
		return mockInterfaces, nil
	})

	// Mock out the likelyHomeRouterIP to return a known gateway.
	tstest.Replace(t, &likelyHomeRouterIP, func() (netip.Addr, bool) {
		return netip.MustParseAddr("192.168.7.1"), true
	})

	gw, my, ok := LikelyHomeRouterIP()
	if !ok {
		t.Fatal("expected success")
	}
	t.Logf("myIP = %v; gw = %v", my, gw)

	if want := netip.MustParseAddr("192.168.7.1"); gw != want {
		t.Errorf("got gateway %v; want %v", gw, want)
	}
	if want := netip.MustParseAddr("192.168.7.100"); my != want {
		t.Errorf("got self IP %v; want %v", my, want)
	}

	// Verify that no IP is returned if there are no IPv4 addresses on
	// local interfaces.
	t.Run("NoIPv4Addrs", func(t *testing.T) {
		tstest.Replace(t, &mockInterfaces, []Interface{
			// Interface that's up, but only has an IPv6 address
			{
				Interface: &net.Interface{
					Index: 2,
					MTU:   1500,
					Name:  "en0",
					Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
				},
				AltAddrs: []net.Addr{
					ipnet("76f9:2e7d:55dd:48e1:48d0:763a:b591:b1bc/64"),
				},
			},
		})

		_, _, ok := LikelyHomeRouterIP()
		if ok {
			t.Fatal("expected no success")
		}
	})
}

func TestLikelyHomeRouterIP_NoMocks(t *testing.T) {
	// Verify that this works properly when called on a real live system,
	// without any mocks.
	gw, my, ok := LikelyHomeRouterIP()
	t.Logf("LikelyHomeRouterIP: gw=%v my=%v ok=%v", gw, my, ok)
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
		if got := isUsableV6(netip.MustParseAddr(test.ip)); got != test.want {
			t.Errorf("isUsableV6(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestStateEqualFilteredIPFilter(t *testing.T) {
	// s1 and s2 are identical, except that an "interesting" interface
	// has gained an "uninteresting" IP address.

	s1 := &State{
		InterfaceIPs: map[string][]netip.Prefix{"x": {
			netip.MustParsePrefix("42.0.0.0/8"),
			netip.MustParsePrefix("169.254.0.0/16"), // link local unicast
		}},
		Interface: map[string]Interface{"x": {Interface: &net.Interface{Name: "x"}}},
	}

	s2 := &State{
		InterfaceIPs: map[string][]netip.Prefix{"x": {
			netip.MustParsePrefix("42.0.0.0/8"),
			netip.MustParsePrefix("169.254.0.0/16"), // link local unicast
			netip.MustParsePrefix("127.0.0.0/8"),    // loopback (added)
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
				InterfaceIPs: map[string][]netip.Prefix{
					"eth0": {
						netip.MustParsePrefix("10.0.0.2/8"),
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
