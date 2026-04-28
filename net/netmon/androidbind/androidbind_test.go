// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package androidbind

import (
	"net"
	"testing"
)

// TestAndroidInterfacesReturnsLoopback is a smoke test that runs only
// under `go test` on Android. It asserts that getifaddrs can find at
// least the loopback interface, which is always present on any
// Android device. Validates that libc getifaddrs is linked and
// returns non-empty results.
func TestAndroidInterfacesReturnsLoopback(t *testing.T) {
	ifs, err := androidInterfaces()
	if err != nil {
		t.Fatalf("androidInterfaces: %v", err)
	}
	if len(ifs) == 0 {
		t.Fatal("expected at least one interface, got 0")
	}
	var haveLoopback bool
	for _, i := range ifs {
		if i.Interface == nil {
			continue
		}
		if i.Interface.Flags&net.FlagLoopback != 0 {
			haveLoopback = true
			break
		}
	}
	if !haveLoopback {
		names := make([]string, 0, len(ifs))
		for _, i := range ifs {
			if i.Interface != nil {
				names = append(names, i.Interface.Name)
			}
		}
		t.Errorf("no loopback interface found in %v", names)
	}
}

func TestCountLeadingOnes(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte{0xff, 0xff, 0xff, 0x00}, 24},         // /24
		{[]byte{0xff, 0xff, 0xff, 0xff}, 32},         // /32
		{[]byte{0x00, 0x00, 0x00, 0x00}, 0},          // /0
		{[]byte{0xff, 0xf0, 0x00, 0x00}, 12},         // /12
		{[]byte{0xff, 0xff, 0xff, 0x80}, 25},         // /25 (8+8+8+1)
	}
	for _, c := range cases {
		if got := countLeadingOnes(c.in); got != c.want {
			t.Errorf("countLeadingOnes(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
