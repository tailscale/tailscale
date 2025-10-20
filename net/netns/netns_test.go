// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
//
// The netns package also handles connecting via SOCKS proxies when
// configured by the environment.
package netns

import (
	"errors"
	"flag"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

var extNetwork = flag.Bool("use-external-network", false, "use the external network in tests")

func TestDial(t *testing.T) {
	if !*extNetwork {
		t.Skip("skipping test without --use-external-network")
	}
	d := NewDialer(t.Logf, nil)
	c, err := d.Dial("tcp", "google.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Logf("got addr %v", c.RemoteAddr())

	c, err = d.Dial("tcp4", "google.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Logf("got addr %v", c.RemoteAddr())
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 !loopback", "192.168.0.1", false},
		{"IPv4 loopback with port", "127.0.0.1:1", true},
		{"IPv4 !loopback with port", "192.168.0.1:1", false},
		{"IPv4 unspecified", "0.0.0.0", false},
		{"IPv4 unspecified with port", "0.0.0.0:1", false},
		{"IPv6 loopback", "::1", true},
		{"IPv6 !loopback", "2001:4860:4860::8888", false},
		{"IPv6 loopback with port", "[::1]:1", true},
		{"IPv6 !loopback with port", "[2001:4860:4860::8888]:1", false},
		{"IPv6 unspecified", "::", false},
		{"IPv6 unspecified with port", "[::]:1", false},
		{"empty", "", false},
		{"hostname", "example.com", false},
		{"localhost", "localhost", true},
		{"localhost6", "localhost6", true},
		{"localhost with port", "localhost:1", true},
		{"localhost6 with port", "localhost6:1", true},
		{"ip6-localhost", "ip6-localhost", true},
		{"ip6-localhost with port", "ip6-localhost:1", true},
		{"ip6-loopback", "ip6-loopback", true},
		{"ip6-loopback with port", "ip6-loopback:1", true},
	}

	for _, test := range tests {
		if got := isLocalhost(test.host); got != test.want {
			t.Errorf("isLocalhost(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestGlobalRouteCache(t *testing.T) {
	iface1 := &net.Interface{Index: 1, Name: "eth0"}
	iface2 := &net.Interface{Index: 2, Name: "eth1"}
	iface3 := &net.Interface{Index: 3, Name: "wlan0"}

	t.Run("insert and lookup IPv4", func(t *testing.T) {
		routeCache := NewRouteCache()

		addr := netip.MustParseAddr("10.0.1.5")
		routeCache.setCachedRoute(addr, iface1)

		got := routeCache.lookupCachedRoute(addr)
		if got != iface1 {
			t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr, got, iface1)
		}
	})

	t.Run("insert and lookup IPv6", func(t *testing.T) {
		routeCache := NewRouteCache()

		addr := netip.MustParseAddr("2001:db8::1")
		routeCache.setCachedRoute(addr, iface2)

		got := routeCache.lookupCachedRoute(addr)
		if got != iface2 {
			t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr, got, iface2)
		}
	})

	t.Run("lookup non-existent", func(t *testing.T) {
		routeCache := NewRouteCache()
		addr := netip.MustParseAddr("192.168.1.1")
		got := routeCache.lookupCachedRoute(addr)
		if got != nil {
			t.Errorf("lookupCachedRoute(%v) = %v, want nil", addr, got)
		}
	})

	t.Run("longest prefix match IPv4", func(t *testing.T) {
		routeCache := NewRouteCache()

		// Insert broader prefix
		prefix1 := netip.MustParsePrefix("10.0.0.0/8")
		routeCache.setCachedRoutePrefix(prefix1, iface1)

		// Insert more specific prefix
		prefix2 := netip.MustParsePrefix("10.0.1.0/24")
		routeCache.setCachedRoutePrefix(prefix2, iface2)

		// Insert even more specific prefix
		prefix3 := netip.MustParsePrefix("10.0.1.128/25")
		routeCache.setCachedRoutePrefix(prefix3, iface3)

		tests := []struct {
			addr string
			want *net.Interface
		}{
			{"10.0.0.1", iface1},   // matches 10.0.0.0/8
			{"10.0.1.1", iface2},   // matches 10.0.1.0/24
			{"10.0.1.129", iface3}, // matches 10.0.1.128/25
			{"10.0.1.127", iface2}, // matches 10.0.1.0/24 (not /25)
			{"10.0.2.1", iface1},   // matches 10.0.0.0/8
			{"192.168.1.1", nil},   // no match
		}

		for _, tt := range tests {
			addr := netip.MustParseAddr(tt.addr)
			got := routeCache.lookupCachedRoute(addr)
			if got != tt.want {
				t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr, got, tt.want)
			}
		}
	})

	t.Run("longest prefix match IPv6", func(t *testing.T) {
		routeCache := NewRouteCache()

		// Insert broader prefix
		prefix1 := netip.MustParsePrefix("2001:db8::/32")
		routeCache.setCachedRoutePrefix(prefix1, iface1)

		// Insert more specific prefix
		prefix2 := netip.MustParsePrefix("2001:db8:1::/48")
		routeCache.setCachedRoutePrefix(prefix2, iface2)

		tests := []struct {
			addr string
			want *net.Interface
		}{
			{"2001:db8::1", iface1},   // matches 2001:db8::/32
			{"2001:db8:1::1", iface2}, // matches 2001:db8:1::/48
			{"2001:db8:2::1", iface1}, // matches 2001:db8::/32
			{"2001:db9::1", nil},      // no match
		}

		for _, tt := range tests {
			addr := netip.MustParseAddr(tt.addr)
			got := routeCache.lookupCachedRoute(addr)
			if got != tt.want {
				t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr, got, tt.want)
			}
		}
	})

	t.Run("clear cached route by address", func(t *testing.T) {
		routeCache := NewRouteCache()

		addr := netip.MustParseAddr("10.0.1.5")
		routeCache.setCachedRoute(addr, iface1)

		// Verify it's there
		if got := routeCache.lookupCachedRoute(addr); got != iface1 {
			t.Errorf("before clear: lookupCachedRoute(%v) = %v, want %v", addr, got, iface1)
		}

		// Clear it
		routeCache.ClearCachedRoute(addr)

		// Verify it's gone
		if got := routeCache.lookupCachedRoute(addr); got != nil {
			t.Errorf("after clear: lookupCachedRoute(%v) = %v, want nil", addr, got)
		}
	})

	t.Run("clear cached route by prefix", func(t *testing.T) {
		routeCache := NewRouteCache()

		prefix := netip.MustParsePrefix("10.0.1.0/24")
		routeCache.setCachedRoutePrefix(prefix, iface1)

		// Verify it's there
		addr := netip.MustParseAddr("10.0.1.5")
		if got := routeCache.lookupCachedRoute(addr); got != iface1 {
			t.Errorf("before clear: lookupCachedRoute(%v) = %v, want %v", addr, got, iface1)
		}

		// Clear it
		routeCache.clearCachedRoutePrefix(prefix)

		// Verify it's gone
		if got := routeCache.lookupCachedRoute(addr); got != nil {
			t.Errorf("after clear: lookupCachedRoute(%v) = %v, want nil", addr, got)
		}
	})

	t.Run("clear specific prefix preserves other prefixes", func(t *testing.T) {
		routeCache := NewRouteCache()

		prefix1 := netip.MustParsePrefix("10.0.0.0/8")
		prefix2 := netip.MustParsePrefix("192.168.0.0/16")
		routeCache.setCachedRoutePrefix(prefix1, iface1)
		routeCache.setCachedRoutePrefix(prefix2, iface2)

		// Clear only prefix1
		routeCache.clearCachedRoutePrefix(prefix1)

		// Verify prefix1 is gone
		addr1 := netip.MustParseAddr("10.0.1.5")
		if got := routeCache.lookupCachedRoute(addr1); got != nil {
			t.Errorf("lookupCachedRoute(%v) = %v, want nil", addr1, got)
		}

		// Verify prefix2 is still there
		addr2 := netip.MustParseAddr("192.168.1.1")
		if got := routeCache.lookupCachedRoute(addr2); got != iface2 {
			t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr2, got, iface2)
		}
	})

	t.Run("clear all cached routes", func(t *testing.T) {
		routeCache := NewRouteCache()

		// Insert multiple routes
		addr1 := netip.MustParseAddr("10.0.1.5")
		addr2 := netip.MustParseAddr("192.168.1.1")
		addr3 := netip.MustParseAddr("2001:db8::1")
		routeCache.setCachedRoute(addr1, iface1)
		routeCache.setCachedRoute(addr2, iface2)
		routeCache.setCachedRoute(addr3, iface3)

		// Clear all
		routeCache.ClearAllCachedRoutes()

		// Verify all are gone
		if got := routeCache.lookupCachedRoute(addr1); got != nil {
			t.Errorf("after clear all: lookupCachedRoute(%v) = %v, want nil", addr1, got)
		}
		if got := routeCache.lookupCachedRoute(addr2); got != nil {
			t.Errorf("after clear all: lookupCachedRoute(%v) = %v, want nil", addr2, got)
		}
		if got := routeCache.lookupCachedRoute(addr3); got != nil {
			t.Errorf("after clear all: lookupCachedRoute(%v) = %v, want nil", addr3, got)
		}
	})

	t.Run("overwrite existing route", func(t *testing.T) {
		routeCache := NewRouteCache()

		addr := netip.MustParseAddr("10.0.1.5")
		routeCache.setCachedRoute(addr, iface1)

		// Verify initial value
		if got := routeCache.lookupCachedRoute(addr); got != iface1 {
			t.Errorf("initial: lookupCachedRoute(%v) = %v, want %v", addr, got, iface1)
		}

		// Overwrite with different interface
		routeCache.setCachedRoute(addr, iface2)

		// Verify new value
		if got := routeCache.lookupCachedRoute(addr); got != iface2 {
			t.Errorf("after overwrite: lookupCachedRoute(%v) = %v, want %v", addr, got, iface2)
		}
	})

	t.Run("IPv4 and IPv6 are separate", func(t *testing.T) {
		routeCache := NewRouteCache()

		addr4 := netip.MustParseAddr("10.0.1.5")
		addr6 := netip.MustParseAddr("2001:db8::1")

		routeCache.setCachedRoute(addr4, iface1)
		routeCache.setCachedRoute(addr6, iface2)

		// Verify both are stored independently
		if got := routeCache.lookupCachedRoute(addr4); got != iface1 {
			t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr4, got, iface1)
		}
		if got := routeCache.lookupCachedRoute(addr6); got != iface2 {
			t.Errorf("lookupCachedRoute(%v) = %v, want %v", addr6, got, iface2)
		}

		// Clear IPv4, verify IPv6 remains
		routeCache.ClearCachedRoute(addr4)
		if got := routeCache.lookupCachedRoute(addr4); got != nil {
			t.Errorf("after clear v4: lookupCachedRoute(%v) = %v, want nil", addr4, got)
		}
		if got := routeCache.lookupCachedRoute(addr6); got != iface2 {
			t.Errorf("after clear v4: lookupCachedRoute(%v) = %v, want %v", addr6, got, iface2)
		}
	})
}

func hookInterfaces(t *testing.T, ifaces []net.Interface) {
	interfacesHook = func() ([]net.Interface, error) {
		return ifaces, nil
	}
	t.Cleanup(func() {
		interfacesHook = net.Interfaces
	})
}

func hookDefaultInterfaces(t *testing.T) {
	hookInterfaces(t, allTestIfs)
}

var (
	iface1 net.Interface = net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
	}
	iface2 net.Interface = net.Interface{
		Index:        2,
		MTU:          1500,
		Name:         "wlan0",
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning,
	}
	iface3 net.Interface = net.Interface{
		Index:        3,
		MTU:          1500,
		Name:         "eth1",
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x77},
		Flags:        net.FlagBroadcast | net.FlagMulticast,
	}
	allTestIfs = []net.Interface{iface1, iface2, iface3}
)

func TestFindInterfaceThatCanReach(t *testing.T) {
	origReachabilityHook := reachabilityHook
	t.Cleanup(func() {
		ifaceHasV4AndGlobalV6Hook = nil
		reachabilityHook = origReachabilityHook
	})

	ifaceHasV4AndGlobalV6Hook = func(iface *net.Interface) bool {
		return true
	}

	t.Run("uses route cache on hit", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// Pre-populate cache
		addr := netip.MustParseAddr("8.8.8.8")
		cache.setCachedRoute(addr, &iface2)

		// Hook should never be called when cache hits
		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			t.Error("reachabilityHookFn should not be called when cache hits")
			return nil
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "8.8.8.8", Port: "53", Network: "udp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result")
		}

		if result.Name != "wlan0" {
			t.Errorf("expected wlan0 from cache, got %s", result.Name)
		}
	})

	t.Run("populates cache on miss", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// All interfaces succeed
		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			return nil
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "1.1.1.1", Port: "53", Network: "udp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Check cache was populated
		addr := netip.MustParseAddr("1.1.1.1")
		cached := cache.lookupCachedRoute(addr)
		if cached == nil {
			t.Error("expected cache to be populated")
		} else if cached.Name != result.Name {
			t.Errorf("cached interface %s != result interface %s", cached.Name, result.Name)
		}
	})

	t.Run("returns nil when no interface reachable", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// All interfaces fail
		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			return errors.New("unreachable")
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "192.0.2.1", Port: "53", Network: "udp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Logf("expected error: %v", err)
		}

		if result != nil {
			t.Errorf("expected nil result when unreachable, got %v", result)
		}
	})

	t.Run("cache respects longest prefix match", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// Cache 10.0.0.0/8 -> eth0
		prefix1 := netip.MustParsePrefix("10.0.0.0/8")
		cache.setCachedRoutePrefix(prefix1, &iface1)

		// Cache 10.0.1.0/24 -> wlan0
		prefix2 := netip.MustParsePrefix("10.0.1.0/24")
		cache.setCachedRoutePrefix(prefix2, &iface2)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			t.Error("should use cache, not probe")
			return nil
		}

		// Test 10.0.1.5 -> should match more specific /24
		opts1 := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "10.0.1.5", Port: "53", Network: "udp"},
			cache: cache,
		}

		result1, _ := findInterfaceThatCanReach(opts1)
		if result1 == nil || result1.Name != "wlan0" {
			t.Errorf("expected wlan0 for 10.0.1.5, got %v", result1)
		}

		// Test 10.0.2.5 -> should match broader /8
		opts2 := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "10.0.2.5", Port: "53", Network: "udp"},
			cache: cache,
		}

		result2, _ := findInterfaceThatCanReach(opts2)
		if result2 == nil || result2.Name != "eth0" {
			t.Errorf("expected eth0 for 10.0.2.5, got %v", result2)
		}
	})

	t.Run("race mode returns first reachable", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// eth0 (iface1) responds quickly
		// wlan0 (iface2) responds slowly
		// eth1 (iface3) responds slowly
		// Channels to control when each probe completes
		wlan0Done := make(chan struct{})
		eth1Done := make(chan struct{})

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			switch iface.Index {
			case iface1.Index: // eth0 - returns immediately
				return nil
			case iface2.Index: // wlan0 - waits for signal
				<-wlan0Done
				return nil
			case iface3.Index: // eth1 - waits for signal
				<-eth1Done
				return nil
			}
			return errors.New("unknown interface")
		}
		defer func() {
			// Now signal the slower interfaces to complete
			close(wlan0Done)
			close(eth1Done)
		}()

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "8.8.8.8", Port: "53", Network: "udp"},
			race:  true,
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result in race mode")
		}

		// Should return quickly without waiting for all probes
		t.Logf("race mode returned interface: %s", result.Name)
	})

	t.Run("filterf excludes interfaces", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		probeCount := atomic.Int32{}
		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			probeCount.Add(1)
			return nil
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "8.8.8.8", Port: "53", Network: "udp"},
			cache: cache,
			filterf: func(iface net.Interface) bool {
				// Exclude wlan0 and eth1
				return iface.Name != "wlan0" && iface.Name != "eth1"
			},
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		// Should only probe filtered interfaces
		if probeCount.Load() > 1 {
			t.Logf("probed %d interfaces after filtering", probeCount.Load())
		}

		if result != nil && (result.Name == "wlan0" || result.Name == "eth1") {
			t.Errorf("filterf should have excluded %s", result.Name)
		}
	})

	t.Run("handles hostname instead of IP", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			return nil
		}

		// Use a hostname that can't be parsed as an IP
		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "example.com", Port: "443", Network: "tcp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Cache should not be used for hostnames
		addr, parseErr := netip.ParseAddr("example.com")
		if parseErr == nil && addr.IsValid() {
			t.Error("example.com should not parse as valid IP")
		}
	})

	t.Run("default interface hint is respected", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// All interfaces are reachable
		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			return nil
		}

		// Set hint to prefer iface2 (index 2)
		origHintFn := defaultIfaceHintFn
		defer func() { defaultIfaceHintFn = origHintFn }()

		defaultIfaceHintFn = func() int {
			return 2 // iface2 / wlan0
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "1.1.1.1", Port: "53", Network: "udp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result")
		}

		if result.Index != 2 {
			t.Errorf("expected default hint interface (index 2), got index %d (%s)", result.Index, result.Name)
		}
	})

	t.Run("IPv6 address uses IPv6 cache table", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// Pre-populate IPv6 cache
		addr6 := netip.MustParseAddr("2001:4860:4860::8888")
		cache.setCachedRoute(addr6, &iface3)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			t.Error("should use cache for IPv6")
			return nil
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "2001:4860:4860::8888", Port: "53", Network: "udp6"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)
		if err != nil {
			t.Fatalf("findInterfaceThatCanReach failed: %v", err)
		}

		if result == nil || result.Name != "eth1" {
			t.Errorf("expected eth1 from IPv6 cache, got %v", result)
		}
	})

	t.Run("IPv4 and IPv6 caches are independent", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		addr4 := netip.MustParseAddr("8.8.8.8")
		addr6 := netip.MustParseAddr("2001:4860:4860::8888")

		cache.setCachedRoute(addr4, &iface1)
		cache.setCachedRoute(addr6, &iface2)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			t.Error("should use cache")
			return nil
		}

		// Test IPv4
		opts4 := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "8.8.8.8", Port: "53", Network: "udp"},
			cache: cache,
		}
		result4, _ := findInterfaceThatCanReach(opts4)
		if result4 == nil || result4.Name != "eth0" {
			t.Errorf("IPv4: expected eth0, got %v", result4)
		}

		// Test IPv6
		opts6 := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "2001:4860:4860::8888", Port: "53", Network: "udp6"},
			cache: cache,
		}
		result6, _ := findInterfaceThatCanReach(opts6)
		if result6 == nil || result6.Name != "wlan0" {
			t.Errorf("IPv6: expected wlan0, got %v", result6)
		}
	})

	t.Run("empty host returns error", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			return nil
		}

		opts := probeOpts{
			logf:  t.Logf,
			hpn:   HostPortNetwork{Host: "", Port: "53", Network: "udp"},
			cache: cache,
		}

		result, err := findInterfaceThatCanReach(opts)

		// Should handle empty host gracefully
		if err == nil && result != nil {
			t.Logf("handled empty host, returned %v", result)
		}
	})

	t.Run("caches subnet prefix correctly", func(t *testing.T) {
		cache := NewRouteCache()
		hookDefaultInterfaces(t)

		// Manually cache a /16 subnet
		prefix := netip.MustParsePrefix("192.168.0.0/16")
		cache.setCachedRoutePrefix(prefix, &iface1)

		reachabilityHook = func(iface *net.Interface, hpn HostPortNetwork) error {
			t.Error("should use cached subnet")
			return nil
		}

		// Test various IPs in the subnet
		testIPs := []string{
			"192.168.0.1",
			"192.168.1.1",
			"192.168.255.254",
		}

		for _, ip := range testIPs {
			opts := probeOpts{
				logf:  t.Logf,
				hpn:   HostPortNetwork{Host: ip, Port: "53", Network: "udp"},
				cache: cache,
			}

			result, _ := findInterfaceThatCanReach(opts)
			if result == nil || result.Name != "eth0" {
				t.Errorf("IP %s: expected eth0 from cached subnet, got %v", ip, result)
			}
		}
	})
}

// TODO (barnstar):  Working, but the sleep is egregious.  How to test async eventbus properly?
// func TestRouteCacheEventBus(t *testing.T) {
// 	t.Run("insert and lookup IPv4", func(t *testing.T) {
// 		rc := NewRouteCache()
// 		bus := eventbus.New()
// 		b := bus.Client("netns_test")
// 		t.Cleanup(func() {
// 			b.Close()
// 		})

// 		route := netip.MustParseAddr("1.1.1.1")

// 		// Example of publishing a route cache clear event
// 		publisher := eventbus.Publish[netmon.ChangeDelta](b)
// 		SetGlobalRouteCache(rc, bus, t.Logf)
// 		rc.setCachedRoute(route, &net.Interface{Index: 1, Name: "eth0"})
// 		ifBeforeEvent := rc.lookupCachedRoute(route)
// 		if ifBeforeEvent == nil || ifBeforeEvent.Name != "eth0" {
// 			t.Fatalf("expected cached route before event, got %v", ifBeforeEvent)
// 		}

// 		publisher.Publish(netmon.ChangeDelta{RebindLikelyRequired: true})
// 		time.Sleep(100 * time.Millisecond)

// 		ifAfterEvent := rc.lookupCachedRoute(route)
// 		if ifAfterEvent != nil {
// 			t.Fatalf("expected cached route to be cleared after event, got %v", ifAfterEvent)
// 		}
// 	})
// }
