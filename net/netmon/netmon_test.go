// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"flag"
	"net"
	"net/netip"
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
			t.Logf("cb: changed=%v, ifSt=%v", d.Major, d.New)
		})
		mon.Start()
		<-done
		t.Logf("%v callbacks", n)
	case "eventbus":
		tw.TimeOut = *monitorDuration
		n := 0
		mon.Start()
		eventbustest.Expect(tw, func(event *ChangeDelta) (bool, error) {
			n++
			t.Logf("cb: changed=%v, ifSt=%v", event.Major, event.New)
			return false, nil // Return false, indicating we wanna look for more events
		})
		t.Logf("%v events", n)
	}
}

// tests (*State).IsMajorChangeFrom
func TestIsMajorChangeFrom(t *testing.T) {
	tests := []struct {
		name   string
		s1, s2 *State
		want   bool
	}{
		{
			name: "eq_nil",
			want: false,
		},
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
						// Brad saw this address coming & going on his home LAN, possibly
						// via an Apple TV Thread routing advertisement? (Issue 9040)
						netip.MustParsePrefix("fd15:bbfa:c583:4fce:f4fb:4ff:fe1a:4148/64"),
					},
				},
			},
			want: true, // TODO(bradfitz): want false (ignore the IPv6 ULA address on foo)
		},
	}
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

			var m Monitor
			m.om = &testOSMon{
				Interesting: func(name string) bool { return true },
			}
			if got := m.IsMajorChangeFrom(tt.s1, tt.s2); got != tt.want {
				t.Errorf("IsMajorChange = %v; want %v", got, tt.want)
			}
		})
	}
}

type testOSMon struct {
	osMon
	Interesting func(name string) bool
}

func (m *testOSMon) IsInterestingInterface(name string) bool {
	if m.Interesting == nil {
		return true
	}
	return m.Interesting(name)
}
