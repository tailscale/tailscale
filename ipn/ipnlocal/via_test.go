// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
)

func TestViaTargetAllowed(t *testing.T) {
	t.Parallel()

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

func TestGenerateViaTargetAdditions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		v        string
		want     []netipx.IPRange
		wantErrs []string
	}{
		{
			name: "empty",
		},
		{
			name: "space",
			v:    " ",
		},
		{
			name:     "invalid-without-comma",
			v:        "asdf",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address"},
		},
		{
			name: "empty-with-comma",
			v:    " , ",
		},
		{
			name: "invalid-with-comma",
			v:    "asdf,fdsa",
			wantErrs: []string{
				"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address",
				"rejecting " + viaAdditionsEnv + " value \"fdsa\": not a range, prefix, or address",
			},
		},
		{
			name: "single-range",
			v:    "100.0.0.0-100.1.0.0",
			want: []netipx.IPRange{netipx.MustParseIPRange("100.0.0.0-100.1.0.0")},
		},
		{
			name: "single-prefix",
			v:    "127.1.0.0/16",
			want: []netipx.IPRange{netipx.MustParseIPRange("127.1.0.0-127.1.255.255")},
		},
		{
			name: "single-addr",
			v:    "255.255.255.255",
			want: []netipx.IPRange{netipx.MustParseIPRange("255.255.255.255-255.255.255.255")},
		},
		{
			name:     "single-ipv6-range",
			v:        "fe80::-fe80::ffff",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " range fe80::-fe80::ffff: not IPv4"},
		},
		{
			name:     "single-ipv6-prefix",
			v:        "fe80::/120",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " prefix fe80::/120: not IPv4"},
		},
		{
			name:     "single-ipv6-addr-bracket",
			v:        "[fe80::]",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"[fe80::]\": not a range, prefix, or address"},
		},
		{
			name:     "single-ipv6-addr-bare",
			v:        "fe80::",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " address fe80::: not IPv4"},
		},
		{
			name:     "mixed-ipv4-ipv6",
			v:        "127.1.0.0/16, fd7a:115c:a1e0:b1a:0:4:7f00:0/120",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " prefix fd7a:115c:a1e0:b1a:0:4:7f00:0/120: not IPv4"},
			want:     []netipx.IPRange{netipx.MustParseIPRange("127.1.0.0-127.1.255.255")},
		},
		{
			name: "multiple",
			v:    "192.0.0.5-192.0.0.10,127.1.0.0/16,8.8.8.8",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
		},
		{
			name: "invalid-in-middle",
			v:    "192.0.0.5-192.0.0.10,asdf,127.1.0.0/16,8.8.8.8",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address"},
		},
		{
			name: "spaces-tabs-newline",
			v:    "\n\n192.0.0.5-192.0.0.10\n ,\t127.1.0.0/16,      8.8.8.8\t\t",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateViaTargetAdditions(tt.v)
			if err == nil {
				if len(tt.wantErrs) > 0 {
					t.Error("returned no errors, want some errors")
				}
			} else {
				var gotErrors []error
				if unwrapper, ok := err.(interface{ Unwrap() []error }); ok {
					gotErrors = unwrapper.Unwrap()
				} else {
					gotErrors = []error{err}
				}

				for i, e := range gotErrors {
					if i >= len(tt.wantErrs) {
						t.Errorf("error[%d] = %v, want no more errors", i, e)
						continue
					}
					if e.Error() != tt.wantErrs[i] {
						t.Errorf("error[%d] = %v, want %v", i, e, tt.wantErrs[i])
					}
				}
				if len(gotErrors) < len(tt.wantErrs) {
					t.Errorf("%d errors found, want %d", len(gotErrors), len(tt.wantErrs))
				}
			}

			if got != nil {
				gotRanges := got.Ranges()
				if !slices.Equal(tt.want, gotRanges) {
					t.Errorf("ipset.Ranges() = %v, want %v", gotRanges, tt.want)
				}
				return
			}
			if tt.want != nil {
				t.Errorf("nil ipset, want ranges to be %v", tt.want)
			}
		})
	}
}
