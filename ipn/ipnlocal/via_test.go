// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
	"tailscale.com/util/must"
)

func TestViaUnmappedTargetAllowed(t *testing.T) {
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
		if got := viaUnmappedTargetAllowed(ip); got != tc.want {
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
			got, err := generateEnvViaTargetAdditions(tt.v)
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

func mapViaPrefix(v4Str string, siteID uint32) netip.Prefix {
	v4 := netip.MustParsePrefix(v4Str)
	return must.Get(tsaddr.MapVia(siteID, v4))
}
func mapViaAddr(v4Str string, siteID uint32) netip.Addr {
	v4 := netip.MustParseAddr(v4Str)
	return must.Get(tsaddr.MapVia(siteID, netip.PrefixFrom(v4, v4.BitLen()))).Addr()
}
func mapViaRange(rangeStr string, siteID uint32) netipx.IPRange {
	v4Range := netipx.MustParseIPRange(rangeStr)
	return netipx.IPRangeFrom(
		must.Get(tsaddr.MapVia(siteID, netip.PrefixFrom(v4Range.From(), v4Range.From().BitLen()))).Addr(),
		must.Get(tsaddr.MapVia(siteID, netip.PrefixFrom(v4Range.To(), v4Range.To().BitLen()))).Addr(),
	)
}

func printMaybeViaAddr(a netip.Addr) string {
	siteID, v4 := tsaddr.UnmapViaWithSiteID(a)
	if v4.IsUnspecified() {
		return v4.String()
	}
	return fmt.Sprintf("%s,%d", v4, siteID)
}

type viaIPRange netipx.IPRange

func (r viaIPRange) String() string {
	ipr := netipx.IPRange(r)
	return fmt.Sprintf("%s-%s", printMaybeViaAddr(ipr.From()), printMaybeViaAddr(ipr.To()))
}

func TestGenerateViaAdvertisedAllowlist(t *testing.T) {
	tests := []struct {
		name             string
		advertisedRoutes []netip.Prefix
		want             []netipx.IPRange
	}{
		{
			name: "empty",
		},
		{
			name: "cloudmeta-exact",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("169.254.169.254/32", 1),
			},
			want: []netipx.IPRange{
				mapViaRange("169.254.169.254-169.254.169.254", 1),
			},
		},
		{
			name: "cloudmeta-inexact",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("169.254.169.0/24", 2),
			},
			want: []netipx.IPRange{
				mapViaRange("169.254.169.0-169.254.169.253", 2),
				mapViaRange("169.254.169.255-169.254.169.255", 2),
			},
		},
		{
			name: "loopback",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("127.0.0.0/8", 3),
			},
			want: []netipx.IPRange{
				mapViaRange("127.0.0.0-127.255.255.255", 3),
			},
		},
		{
			name: "link-local",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("169.254.0.0/16", 4),
			},
			want: []netipx.IPRange{
				mapViaRange("169.254.0.0-169.254.42.41", 4),
				mapViaRange("169.254.42.43-169.254.169.253", 4),
				mapViaRange("169.254.169.255-169.254.255.255", 4),
			},
		},
		{
			name: "cgnat",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("100.64.0.0/10", 5),
			},
			want: []netipx.IPRange{
				mapViaRange("100.64.0.0-100.100.100.99", 5),
				mapViaRange("100.100.100.101-100.100.100.199", 5),
				mapViaRange("100.100.100.201-100.127.255.255", 5),
			},
		},
		{
			name: "non-via",
			advertisedRoutes: []netip.Prefix{
				netip.MustParsePrefix("8.0.0.0/8"),
			},
		},
		{
			name: "many-site-id",
			advertisedRoutes: []netip.Prefix{
				mapViaPrefix("169.0.0.0/8", 4),
				mapViaPrefix("169.254.169.254/32", 4),
				mapViaPrefix("100.100.0.0/16", 4),
				mapViaPrefix("192.168.32.0/24", 4),
				mapViaPrefix("169.254.0.0/16", 5),
				mapViaPrefix("10.0.0.0/8", 5),
				mapViaPrefix("169.254.169.254/32", 5),
				mapViaPrefix("169.254.169.0/24", 6),
				mapViaPrefix("100.0.0.0/8", 7),
				mapViaPrefix("100.100.100.100/32", 7),
				mapViaPrefix("192.0.2.0/24", 7),
			},
			want: []netipx.IPRange{
				mapViaRange("100.100.0.0-100.100.100.99", 4),
				mapViaRange("100.100.100.101-100.100.100.199", 4),
				mapViaRange("100.100.100.201-100.100.255.255", 4),
				mapViaRange("169.254.169.254-169.254.169.254", 4),
				mapViaRange("169.254.0.0-169.254.42.41", 5),
				mapViaRange("169.254.42.43-169.254.255.255", 5),
				mapViaRange("169.254.169.0-169.254.169.253", 6),
				mapViaRange("169.254.169.255-169.254.169.255", 6),
				mapViaRange("100.100.100.100-100.100.100.100", 7),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateViaAdvertisedAllowlist(views.SliceOf(tt.advertisedRoutes))
			if got == nil {
				if tt.want != nil {
					t.Errorf("nil, want %s", tt.want)
				}
				return
			}
			if tt.want == nil {
				t.Errorf("%s, want nil", got)
				return
			}
			wantFormatted := make([]viaIPRange, 0, len(tt.want))
			for _, r := range tt.want {
				wantFormatted = append(wantFormatted, viaIPRange(r))
			}
			gotRanges := got.Ranges()
			gotFormatted := make([]viaIPRange, 0, len(gotRanges))
			for _, r := range gotRanges {
				gotFormatted = append(gotFormatted, viaIPRange(r))
			}

			if diff := cmp.Diff(
				gotFormatted,
				wantFormatted,
				cmpopts.EquateComparable(viaIPRange{}),
			); diff != "" {
				t.Errorf("ranges don't match (-got +want)\n\n%s", diff)
			}
		})
	}
}
