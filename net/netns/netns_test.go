// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"flag"
	"testing"
)

var extNetwork = flag.Bool("use-external-network", false, "use the external network in tests")

func TestDial(t *testing.T) {
	if !*extNetwork {
		t.Skip("skipping test without --use-external-network")
	}
	d := NewDialer()
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
