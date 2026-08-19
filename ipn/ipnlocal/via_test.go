// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"
)

func TestViaTargetAllowed(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", true},
		{"169.254.169.254", false}, // cloud instance metadata
		{"169.254.0.1", false},     // other link-local
		{"127.0.0.1", false},       // loopback
		{"127.255.0.1", false},
		{"10.9.4.99", true},      // normal LAN host
		{"192.168.50.254", true}, // last routable host on a /24 still allowed
		{"0.0.0.0", false},       // Linux connect() treats as localhost
		{"255.255.255.255", false},
		{"192.168.50.128", true},
		{"10.100.200.5", true},
		{"10.1.2.255", true}, // last octet 255 is not inherently broadcast
		{"172.16.0.9", true},
		{"192.168.50.63", true},
		{"224.0.0.1", false}, // multicast
		{"239.255.252.250", false},
		{"10.20.30.40", true},
		{"198.51.100.7", true},
		{"169.254.169.1", false}, // other link-local
		{"255.0.0.5", true},
		{"10.9.8.7", true},
		{"192.168.1.254", true},
		{"10.0.255.200", true}, // host in a /16 whose last octet isn't 0/255
		{"224.0.0.251", false},
		{"100.64.9.8", false},
		{"192.168.5.10", true},
		{"172.16.255.254", true}, // last host of a /16 (last octet 254) allowed
		{"127.1.2.3", false},
		{"198.18.0.10", true},
		{"239.255.255.250", false}, // SSDP multicast
		{"192.168.50.128", true},
		{"169.254.100.200", false}, // link-local
		{"10.9.4.255", true},       // last octet 255 is not inherently broadcast
		{"224.0.1.129", false},
		{"8.20.30.40", true},
		{"192.168.50.255", true}, // last octet 255 is not inherently broadcast
		{"10.11.12.13", true},
		{"239.1.2.3", false},
		{"100.64.0.1", false}, // tailnet CGNAT: would proxy as this node
		{"100.100.100.100", false},
		{"::1", false},
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.ip)
		if got := viaTargetAllowed(ip); got != tc.want {
			t.Errorf("viaTargetAllowed(%v) = %v, want %v", ip, got, tc.want)
		}
	}
}
