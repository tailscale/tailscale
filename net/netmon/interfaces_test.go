// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/tstest"
)

func TestGetState(t *testing.T) {
	st, err := getState("")
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.MarshalIndent(st, "", "\t")
	if err != nil {
		t.Errorf("JSON: %v", err)
	}
	t.Logf("Got: %s", j)
	t.Logf("As string: %s", st)
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
	tstest.Replace(t, &likelyHomeRouterIP, func() (netip.Addr, netip.Addr, bool) {
		return netip.MustParseAddr("192.168.7.1"), netip.Addr{}, true
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

// https://github.com/tailscale/tailscale/issues/10466
func TestLikelyHomeRouterIP_Prefix(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, ipnet, err := net.ParseCIDR(s)
		ipnet.IP = ip
		if err != nil {
			t.Fatal(err)
		}
		return ipnet
	}

	mockInterfaces := []Interface{
		// Valid and running interface that doesn't have a route to the
		// internet, and comes before the interface that does.
		{
			Interface: &net.Interface{
				Index: 1,
				MTU:   1500,
				Name:  "docker0",
				Flags: net.FlagUp |
					net.FlagBroadcast |
					net.FlagMulticast |
					net.FlagRunning,
			},
			AltAddrs: []net.Addr{
				ipnet("172.17.0.0/16"),
			},
		},

		// Fake interface with a gateway to the internet.
		{
			Interface: &net.Interface{
				Index: 2,
				MTU:   1500,
				Name:  "fake0",
				Flags: net.FlagUp |
					net.FlagBroadcast |
					net.FlagMulticast |
					net.FlagRunning,
			},
			AltAddrs: []net.Addr{
				ipnet("192.168.7.100/24"),
			},
		},
	}

	// Mock out the responses from netInterfaces()
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
		return mockInterfaces, nil
	})

	// Mock out the likelyHomeRouterIP to return a known gateway.
	tstest.Replace(t, &likelyHomeRouterIP, func() (netip.Addr, netip.Addr, bool) {
		return netip.MustParseAddr("192.168.7.1"), netip.Addr{}, true
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
}

func TestLikelyHomeRouterIP_NoMocks(t *testing.T) {
	// Verify that this works properly when called on a real live system,
	// without any mocks.
	gw, my, ok := LikelyHomeRouterIP()
	t.Logf("LikelyHomeRouterIP: gw=%v my=%v ok=%v", gw, my, ok)
}

// TestLocalAddresses_ULA verifies the handling of IPv6 Unique Local Addresses
// (ULA, fc00::/7) in LocalAddresses.
//
// By default ULA addresses are only used as a fallback when no other addresses
// are present. Setting TS_INCLUDE_ULA_ENDPOINTS=true promotes them to
// regular endpoints, enabling direct LAN connectivity without DERP.
func TestLocalAddresses_ULA(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		ipnet.IP = ip
		return ipnet
	}

	// Interface with both RFC 1918 IPv4 and ULA IPv6, as seen on a
	// typical LAN with a ULA-only IPv6 setup (no global IPv6 from ISP).
	mixedIfaces := []Interface{
		{
			Interface: &net.Interface{
				Index: 1,
				MTU:   1500,
				Name:  "en0",
				Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
			},
			AltAddrs: []net.Addr{
				ipnet("10.0.1.5/16"),
				ipnet("fd66:6401:8e8a::1/64"),
			},
		},
	}

	t.Run("ULAExcludedByDefaultWhenRFC1918Present", func(t *testing.T) {
		tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
			return mixedIfaces, nil
		})
		regular, _, err := LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Addr{netip.MustParseAddr("10.0.1.5")}
		if !addrsEqual(regular, want) {
			t.Errorf("LocalAddresses() regular = %v; want %v (ULA should be excluded by default)", regular, want)
		}
	})

	t.Run("ULAIncludedAsFallbackWhenNoOtherAddresses", func(t *testing.T) {
		// Simulate an environment with only ULA (e.g. Google Cloud Run).
		ulaOnlyIfaces := []Interface{
			{
				Interface: &net.Interface{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
				},
				AltAddrs: []net.Addr{
					ipnet("fddf:3978:feb1:d745::1/64"),
				},
			},
		}
		tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
			return ulaOnlyIfaces, nil
		})
		regular, _, err := LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Addr{netip.MustParseAddr("fddf:3978:feb1:d745::1")}
		if !addrsEqual(regular, want) {
			t.Errorf("LocalAddresses() regular = %v; want %v (ULA should be used as fallback)", regular, want)
		}
	})

	t.Run("TailscaleULAAlwaysExcluded", func(t *testing.T) {
		// Tailscale's own ULA range (fd7a:115c:a1e0::/48) must never be
		// reported as a local endpoint — neither by default nor with the
		// knob enabled.
		tsIfaces := []Interface{
			{
				Interface: &net.Interface{
					Index: 1,
					MTU:   1500,
					Name:  "en0",
					Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
				},
				AltAddrs: []net.Addr{
					ipnet("10.0.1.5/16"),
					ipnet("fd7a:115c:a1e0::1/128"), // Tailscale ULA — must be excluded
				},
			},
		}
		want := []netip.Addr{netip.MustParseAddr("10.0.1.5")}

		for _, enabled := range []bool{false, true} {
			val := ""
			if enabled {
				val = "true"
			}
			envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", val)
			t.Cleanup(func() { envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", "") })

			tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
				return tsIfaces, nil
			})
			regular, _, err := LocalAddresses()
			if err != nil {
				t.Fatal(err)
			}
			if !addrsEqual(regular, want) {
				t.Errorf("TS_INCLUDE_ULA_ENDPOINTS=%v: LocalAddresses() = %v; want %v (Tailscale ULA should always be excluded)", enabled, regular, want)
			}
		}
	})

	t.Run("TS_INCLUDE_ULA_ENDPOINTSPromotesULAToRegular", func(t *testing.T) {
		envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", "true")
		t.Cleanup(func() { envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", "") })

		tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
			return mixedIfaces, nil
		})
		regular, _, err := LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Addr{
			netip.MustParseAddr("10.0.1.5"),
			netip.MustParseAddr("fd66:6401:8e8a::1"),
		}
		if !addrsEqual(regular, want) {
			t.Errorf("LocalAddresses() with TS_INCLUDE_ULA_ENDPOINTS regular = %v; want %v", regular, want)
		}
	})

	t.Run("TS_INCLUDE_ULA_ENDPOINTSPreservesIPv4LinkLocalFallback", func(t *testing.T) {
		envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", "true")
		t.Cleanup(func() { envknob.Setenv("TS_INCLUDE_ULA_ENDPOINTS", "") })

		ulaAndLinkLocalIfaces := []Interface{
			{
				Interface: &net.Interface{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
				},
				AltAddrs: []net.Addr{
					ipnet("169.254.10.20/16"),
					ipnet("fddf:3978:feb1:d745::1/64"),
				},
			},
		}
		tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
			return ulaAndLinkLocalIfaces, nil
		})
		regular, _, err := LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Addr{
			netip.MustParseAddr("169.254.10.20"),
			netip.MustParseAddr("fddf:3978:feb1:d745::1"),
		}
		if !addrsEqual(regular, want) {
			t.Errorf("LocalAddresses() with TS_INCLUDE_ULA_ENDPOINTS regular = %v; want %v (link-local fallback should be preserved)", regular, want)
		}
	})
}

// addrsEqual reports whether a and b contain the same set of addresses,
// regardless of order.
func addrsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[netip.Addr]bool, len(a))
	for _, ip := range a {
		set[ip] = true
	}
	for _, ip := range b {
		if !set[ip] {
			return false
		}
	}
	return true
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
		{"zeros", "0::0", false},
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
					"lo": {
						Interface: &net.Interface{},
					},
				},
				InterfaceIPs: map[string][]netip.Prefix{
					"eth0": {
						netip.MustParsePrefix("10.0.0.2/8"),
					},
					"lo": {},
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
						Interface: &net.Interface{
							Flags: net.FlagUp,
						},
					},
				},
			},
			want: `interfaces.State{defaultRoute=foo (a foo thing) ifs={foo:[]} v4=false v6=false}`,
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

// tests (*State).Equal
func TestEqual(t *testing.T) {
	pfxs := func(addrs ...string) (ret []netip.Prefix) {
		for _, addr := range addrs {
			ret = append(ret, netip.MustParsePrefix(addr))
		}
		return ret
	}

	tests := []struct {
		name   string
		s1, s2 *State
		want   bool // implies !wantMajor
	}{
		{
			name: "eq_nil",
			want: true,
		},
		{
			name: "nil_mix",
			s2:   new(State),
			want: false,
		},
		{
			name: "eq",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			want: true,
		},
		{
			name: "default-route-changed",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			want: false,
		},
		{
			name: "some-interface-ips-changed",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.3/16")},
				},
			},
			want: false,
		},
		{
			name: "altaddrs-changed",
			s1: &State{
				Interface: map[string]Interface{
					"foo": {AltAddrs: []net.Addr{&net.TCPAddr{IP: net.ParseIP("1.2.3.4")}}},
				},
			},
			s2: &State{
				Interface: map[string]Interface{
					"foo": {AltAddrs: []net.Addr{&net.TCPAddr{IP: net.ParseIP("5.6.7.8")}}},
				},
			},
			want: false,
		},

		// See tailscale/corp#19124
		{
			name: "interface-removed",
			s1: &State{
				InterfaceIPs: map[string][]netip.Prefix{
					"rmnet16":    pfxs("2607:1111:2222:3333:4444:5555:6666:7777/64"),
					"rmnet17":    pfxs("2607:9999:8888:7777:666:5555:4444:3333/64"),
					"tun0":       pfxs("100.64.1.2/32", "fd7a:115c:a1e0::1/128"),
					"v4-rmnet16": pfxs("192.0.0.4/32"),
					"wlan0":      pfxs("10.0.0.111/24"), // removed below
				},
			},
			s2: &State{
				InterfaceIPs: map[string][]netip.Prefix{
					"rmnet16":    pfxs("2607:1111:2222:3333:4444:5555:6666:7777/64"),
					"rmnet17":    pfxs("2607:9999:8888:7777:666:5555:4444:3333/64"),
					"tun0":       pfxs("100.64.1.2/32", "fd7a:115c:a1e0::1/128"),
					"v4-rmnet16": pfxs("192.0.0.4/32"),
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s2.Equal(tt.s1); got != tt.want {
				t.Errorf("Equal = %v; want %v", got, tt.want)
			}
		})
	}
}
