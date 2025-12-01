// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"flag"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
)

func TestMonitorStartClose(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	if err := mon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorJustClose(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if err := mon.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorInjectEvent(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()

	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	got := make(chan bool, 1)
	mon.RegisterChangeCallback(func(*ChangeDelta) {
		select {
		case got <- true:
		default:
		}
	})
	mon.Start()
	mon.InjectEvent()
	select {
	case <-got:
		// Pass.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for callback")
	}
}

func TestMonitorInjectEventOnBus(t *testing.T) {
	bus := eventbustest.NewBus(t)

	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	tw := eventbustest.NewWatcher(t, bus)

	mon.Start()
	mon.InjectEvent()
	if err := eventbustest.Expect(tw, eventbustest.Type[ChangeDelta]()); err != nil {
		t.Error(err)
	}
}

var (
	monitor         = flag.String("monitor", "", `go into monitor mode like 'route monitor'; test never terminates. Value can be either "raw" or "callback"`)
	monitorDuration = flag.Duration("monitor-duration", 0, "if non-zero, how long to run TestMonitorMode. Zero means forever.")
)

func TestMonitorMode(t *testing.T) {
	switch *monitor {
	case "":
		t.Skip("skipping non-test without --monitor")
	case "raw", "callback", "eventbus":
	default:
		t.Skipf(`invalid --monitor value: must be "raw", "callback" or "eventbus"`)
	}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	switch *monitor {
	case "raw":
		var closed atomic.Bool
		if *monitorDuration != 0 {
			t := time.AfterFunc(*monitorDuration, func() {
				closed.Store(true)
				mon.Close()
			})
			defer t.Stop()
		}
		for {
			msg, err := mon.om.Receive()
			if closed.Load() {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("msg: %#v", msg)
		}
	case "callback":
		var done <-chan time.Time
		if *monitorDuration != 0 {
			t := time.NewTimer(*monitorDuration)
			defer t.Stop()
			done = t.C
		}
		n := 0
		mon.RegisterChangeCallback(func(d *ChangeDelta) {
			n++
			t.Logf("cb: changed=%v, ifSt=%v", d.RebindLikelyRequired, d.CurrentState())
		})
		mon.Start()
		<-done
		t.Logf("%v callbacks", n)
	case "eventbus":
		time.AfterFunc(*monitorDuration, bus.Close)
		n := 0
		mon.Start()
		eventbustest.Expect(tw, func(event *ChangeDelta) (bool, error) {
			n++
			t.Logf("cb: changed=%v, ifSt=%v", event.RebindLikelyRequired, event.CurrentState())
			return false, nil // Return false, indicating we wanna look for more events
		})
		t.Logf("%v events", n)
	}
}

// tests (*ChangeDelta).RebindRequired
func TestRebindRequired(t *testing.T) {
	// s1 cannot be nil by definition
	tests := []struct {
		name     string
		s1, s2   *State
		tsIfName string
		want     bool
	}{
		{
			name: "nil_mix",
			s2:   new(State),
			want: true,
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
			want: false,
		},
		{
			name: "new-with-no-addr",
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
					"bar": {},
				},
			},
			want: false,
		},
		{
			name:     "ignore-tailscale-interface-appearing",
			tsIfName: "tailscale0",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo":        {netip.MustParsePrefix("10.0.1.2/16")},
					"tailscale0": {netip.MustParsePrefix("100.69.4.20/32")},
				},
			},
			want: false,
		},
		{
			name:     "ignore-tailscale-interface-disappearing",
			tsIfName: "tailscale0",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo":        {netip.MustParsePrefix("10.0.1.2/16")},
					"tailscale0": {netip.MustParsePrefix("100.69.4.20/32")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			want: false,
		},
		{
			name: "new-with-multicast-addr",
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
					"bar": {netip.MustParsePrefix("224.0.0.1/32")},
				},
			},
			want: false,
		},
		{
			name: "old-with-addr-dropped",
			s1: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
					"bar": {netip.MustParsePrefix("192.168.0.1/32")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"bar": {netip.MustParsePrefix("192.168.0.1/32")},
				},
			},
			want: true,
		},
		{
			name: "old-with-no-addr-dropped",
			s1: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {},
					"bar": {netip.MustParsePrefix("192.168.0.1/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"bar": {netip.MustParsePrefix("192.168.0.1/16")},
				},
			},
			want: false,
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
			want: true,
		},
		{
			name: "some-interesting-ip-changed",
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
			want: true,
		},
		{
			// (barnstar) TODO: ULA addresses are only useful in some contexts,
			// so maybe this shouldn't trigger rebinds after all? Needs more thought.
			name: "ipv6-ula-addressed-appeared",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {
						netip.MustParsePrefix("10.0.1.2/16"),
						netip.MustParsePrefix("fd15:bbfa:c583:4fce:f4fb:4ff:fe1a:4148/64"),
					},
				},
			},
			want: true,
		},
		{
			// (barnstar) TODO: ULA addresses are only useful in some contexts,
			// so maybe this shouldn't trigger rebinds after all? Needs more thought.
			name: "ipv6-ula-addressed-disappeared",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {
						netip.MustParsePrefix("10.0.1.2/16"),
						netip.MustParsePrefix("fd15:bbfa:c583:4fce:f4fb:4ff:fe1a:4148/64"),
					},
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
			name: "ipv6-link-local-addressed-appeared",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {netip.MustParsePrefix("10.0.1.2/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {
						netip.MustParsePrefix("10.0.1.2/16"),
						netip.MustParsePrefix("fe80::f242:25ff:fe64:b280/64"),
					},
				},
			},
			want: false,
		},
		{
			name: "ipv6-addressed-changed",
			s1: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {
						netip.MustParsePrefix("10.0.1.2/16"),
						netip.MustParsePrefix("2001::f242:25ff:fe64:b280/64"),
						netip.MustParsePrefix("fe80::f242:25ff:fe64:b280/64"),
					},
				},
			},
			s2: &State{
				DefaultRouteInterface: "foo",
				InterfaceIPs: map[string][]netip.Prefix{
					"foo": {
						netip.MustParsePrefix("10.0.1.2/16"),
						netip.MustParsePrefix("2001::beef:8bad:f00d:b280/64"),
						netip.MustParsePrefix("fe80::f242:25ff:fe64:b280/64"),
					},
				},
			},
			want: true,
		},
		{
			name: "have-addr-changed",
			s1: &State{
				HaveV6: false,
				HaveV4: false,
			},

			s2: &State{
				HaveV6: true,
				HaveV4: true,
			},
			want: true,
		},
		{
			name: "have-addr-unchanged",
			s1: &State{
				HaveV6: true,
				HaveV4: true,
			},

			s2: &State{
				HaveV6: true,
				HaveV4: true,
			},
			want: false,
		},
		{
			name: "new-is-less-expensive",
			s1: &State{
				IsExpensive: true,
			},

			s2: &State{
				IsExpensive: false,
			},
			want: true,
		},
		{
			name: "new-is-more-expensive",
			s1: &State{
				IsExpensive: false,
			},

			s2: &State{
				IsExpensive: true,
			},
			want: false,
		},
		{
			name: "uninteresting-interface-added",
			s1: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"bar": {netip.MustParsePrefix("192.168.0.1/16")},
				},
			},
			s2: &State{
				DefaultRouteInterface: "bar",
				InterfaceIPs: map[string][]netip.Prefix{
					"bar":    {netip.MustParsePrefix("192.168.0.1/16")},
					"boring": {netip.MustParsePrefix("fd7a:115c:a1e0:ab12:4843:cd96:625e:13ce/64")},
				},
			},
			want: false,
		},
	}

	withIsInterestingInterface(t, func(ni Interface, pfxs []netip.Prefix) bool {
		return !strings.HasPrefix(ni.Name, "boring")
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Populate dummy interfaces where missing.
			for _, s := range []*State{tt.s1, tt.s2} {
				if s == nil {
					continue
				}
				for name := range s.InterfaceIPs {
					if _, ok := s.Interface[name]; !ok {
						mak.Set(&s.Interface, name, Interface{Interface: &net.Interface{
							Name: name,
						}})
					}
				}
			}

			cd, err := NewChangeDelta(tt.s1, tt.s2, false, tt.tsIfName, true)
			if err != nil {
				t.Fatalf("NewChangeDelta error: %v", err)
			}
			_ = cd // in case we need it later
			if got := cd.RebindLikelyRequired; got != tt.want {
				t.Errorf("RebindRequired = %v; want %v", got, tt.want)
			}
		})
	}
}

func withIsInterestingInterface(t *testing.T, fn func(Interface, []netip.Prefix) bool) {
	t.Helper()
	old := IsInterestingInterface
	IsInterestingInterface = fn
	t.Cleanup(func() { IsInterestingInterface = old })
}

func TestIncludesRoutableIP(t *testing.T) {
	routable := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("10.0.0.1/24"),          // RFC1918 IPv4 (private)
		netip.MustParsePrefix("172.16.0.1/12"),        // RFC1918 IPv4 (private)
		netip.MustParsePrefix("192.168.1.1/24"),       // RFC1918 IPv4 (private)
		netip.MustParsePrefix("fd15:dead:beef::1/64"), // IPv6 ULA
		netip.MustParsePrefix("2001:db8::1/64"),       // global IPv6
	}

	nonRoutable := []netip.Prefix{
		netip.MustParsePrefix("ff00::/8"),     // multicast IPv6 (should be filtered)
		netip.MustParsePrefix("fe80::1/64"),   // link-local IPv6
		netip.MustParsePrefix("::1/128"),      // loopback IPv6
		netip.MustParsePrefix("::/128"),       // unspecified IPv6
		netip.MustParsePrefix("224.0.0.1/32"), // multicast IPv4
		netip.MustParsePrefix("127.0.0.1/32"), // loopback IPv4
	}

	got, want := filterRoutableIPs(
		append(nonRoutable, routable...),
	), routable

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterRoutableIPs returned %v; want %v", got, want)
	}
}

func TestPrefixesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []netip.Prefix
		want bool
	}{
		{
			name: "empty",
			a:    []netip.Prefix{},
			b:    []netip.Prefix{},
			want: true,
		},
		{
			name: "single-equal",
			a:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			b:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			want: true,
		},
		{
			name: "single-different",
			a:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			b:    []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
			want: false,
		},
		{
			name: "unordered-equal",
			a: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.1/24"),
				netip.MustParsePrefix("10.0.2.1/24"),
			},
			b: []netip.Prefix{
				netip.MustParsePrefix("10.0.2.1/24"),
				netip.MustParsePrefix("10.0.0.1/24"),
			},
			want: true,
		},
		{
			name: "subset",
			a: []netip.Prefix{
				netip.MustParsePrefix("10.0.2.1/24"),
			},
			b: []netip.Prefix{
				netip.MustParsePrefix("10.0.2.1/24"),
				netip.MustParsePrefix("10.0.0.1/24"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prefixesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("prefixesEqual(%v, %v) = %v; want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestForeachInterface(t *testing.T) {
	tests := []struct {
		name  string
		addrs []net.Addr
		want  []string
	}{
		{
			name: "Mixed_IPv4_and_IPv6",
			addrs: []net.Addr{
				&net.IPNet{IP: net.IPv4(1, 2, 3, 4), Mask: net.CIDRMask(24, 32)},
				&net.IPAddr{IP: net.IP{5, 6, 7, 8}, Zone: ""},
				&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
				&net.IPAddr{IP: net.ParseIP("2001:db8::2"), Zone: ""},
			},
			want: []string{"1.2.3.4", "5.6.7.8", "2001:db8::1", "2001:db8::2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			ifaces := InterfaceList{
				{
					Interface: &net.Interface{Name: "eth0"},
					AltAddrs:  tt.addrs,
				},
			}
			ifaces.ForeachInterface(func(iface Interface, prefixes []netip.Prefix) {
				for _, prefix := range prefixes {
					ip := prefix.Addr()
					got = append(got, ip.String())
				}
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
