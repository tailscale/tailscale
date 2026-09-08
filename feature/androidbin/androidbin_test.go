// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package androidbin

import (
	"net"
	"testing"

	"tailscale.com/net/netmon"
)

func TestFallbackInterfacesNotAndroid(t *testing.T) {
	if onAndroid() {
		t.Skip("running on Android")
	}
	if _, err := fallbackInterfaces(); err == nil {
		t.Fatal("fallbackInterfaces succeeded off Android; want error")
	}
}

func TestOutboundIP(t *testing.T) {
	ip, ok := outboundIP("udp4", "8.8.8.8:53")
	if !ok {
		t.Skip("no IPv4 route (offline?)")
	}
	if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() {
		t.Errorf("outboundIP = %v; want global unicast IPv4", ip)
	}
	t.Logf("outbound IPv4 source: %v", ip)
}

func TestSyntheticInterface(t *testing.T) {
	ifs, err := syntheticFor(t)
	if err != nil {
		t.Skip("no routes (offline?)")
	}
	if len(ifs) != 1 {
		t.Fatalf("got %d interfaces; want 1", len(ifs))
	}
	nif := ifs[0]
	if !nif.IsUp() {
		t.Error("synthetic interface is not up")
	}
	addrs, err := nif.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses on synthetic interface")
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			t.Errorf("address %v is %T; want *net.IPNet", a, a)
			continue
		}
		if ipn.IP.IsLoopback() || ipn.IP.IsUnspecified() {
			t.Errorf("address %v is not a usable source address", ipn)
		}
	}
}

// syntheticFor builds the synthetic interface list regardless of
// whether the test machine is Android, by skipping the onAndroid
// check that fallbackInterfaces performs.
func syntheticFor(t *testing.T) ([]netmon.Interface, error) {
	t.Helper()
	return buildSynthetic()
}
