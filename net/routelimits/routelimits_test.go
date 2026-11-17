// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routelimits

import (
	"net/netip"
	"testing"
)

func TestIsDisallowedForRouting(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"169.254.169.254", true}, // cloud instance metadata
		{"169.254.0.1", true},     // other link-local
		{"127.0.0.1", true},       // loopback
		{"127.255.0.1", true},
		{"10.9.4.99", false},      // normal LAN host
		{"192.168.50.254", false}, // last routable host on a /24 still allowed
		{"0.0.0.0", true},         // Linux connect() treats as localhost
		{"255.255.255.255", true},
		{"192.168.50.128", false},
		{"10.100.200.5", false},
		{"10.1.2.255", false}, // last octet 255 is not inherently broadcast
		{"172.16.0.9", false},
		{"192.168.50.63", false},
		{"224.0.0.1", true}, // multicast
		{"239.255.252.250", true},
		{"10.20.30.40", false},
		{"198.51.100.7", false},
		{"169.254.169.1", true}, // other link-local
		{"255.0.0.5", false},
		{"10.9.8.7", false},
		{"192.168.1.254", false},
		{"10.0.255.200", false}, // host in a /16 whose last octet isn't 0/255
		{"224.0.0.251", true},
		{"100.64.9.8", true},
		{"192.168.5.10", false},
		{"172.16.255.254", false}, // last host of a /16 (last octet 254) allowed
		{"127.1.2.3", true},
		{"198.18.0.10", false},
		{"239.255.255.250", true}, // SSDP multicast
		{"192.168.50.128", false},
		{"169.254.100.200", true}, // link-local
		{"10.9.4.255", false},     // last octet 255 is not inherently broadcast
		{"224.0.1.129", true},
		{"8.20.30.40", false},
		{"192.168.50.255", false}, // last octet 255 is not inherently broadcast
		{"10.11.12.13", false},
		{"239.1.2.3", true},
		{"100.64.0.1", true}, // tailnet CGNAT: would proxy as this node
		{"100.100.100.100", true},
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fd00:ec2::254", true},            // aws IMDS
		{"fd00:ec2::253", true},            // route53
		{"fd20:ce::254", true},             // gcp metadata
		{"fd7a:115c:a1e0::53", true},       // tailscale IPv6 service IP
		{"fd7a:115c:a1e0:1:2:3:4:5", true}, // arbitrary tailscale ULA
		{"fd7a:1234:5678::1", false},       // arbitrary non-tailscale ULA
		{"2606:b740:49::1", false},         // arbitrary globally routable IPv6
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.ip)
		if got := IsDisallowed(ip); got != tc.want {
			t.Errorf("IsDisallowedForRouting(%v) = %v, want %v", ip, got, tc.want)
		}
	}
}
