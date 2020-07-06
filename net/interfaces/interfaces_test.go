// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"net"
	"testing"
)

func TestIsTailscaleIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"100.81.251.94", true},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		got := IsTailscaleIP(ip)
		if got != tt.want {
			t.Errorf("F(%q) = %v; want %v", tt.ip, got, tt.want)
		}
	}
}

func TestGetState(t *testing.T) {
	st, err := GetState()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %#v", st)

	st2, err := GetState()
	if err != nil {
		t.Fatal(err)
	}

	if !st.Equal(st2) {
		// let's assume nobody was changing the system network interfaces between
		// the two GetState calls.
		t.Fatal("two States back-to-back were not equal")
	}
}

func TestLikelyHomeRouterIP(t *testing.T) {
	ip, ok := LikelyHomeRouterIP()
	t.Logf("got %v, %v", ip, ok)
}
