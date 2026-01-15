// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ingressservices

import (
	"net/netip"
	"testing"
	"time"
)

func TestConfigEqualIgnoringResolved(t *testing.T) {
	tests := []struct {
		name     string
		a        *Config
		b        *Config
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "first nil",
			a:        nil,
			b:        &Config{},
			expected: false,
		},
		{
			name:     "second nil",
			a:        &Config{},
			b:        nil,
			expected: false,
		},
		{
			name: "externalName same without resolved",
			a: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				TailscaleServiceIPv6: netip.MustParseAddr("fd7a:115c:a1e0::1"),
			},
			b: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				TailscaleServiceIPv6: netip.MustParseAddr("fd7a:115c:a1e0::1"),
			},
			expected: true,
		},
		{
			name: "externalName same with resolved IPs ignored",
			a: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			},
			b: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			},
			expected: true,
		},
		{
			name: "externalName different name",
			a: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			},
			b: &Config{
				ExternalName:         "other.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			},
			expected: false,
		},
		{
			name: "externalName different tailscale IP",
			a: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			},
			b: &Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.2"),
			},
			expected: false,
		},
		{
			name: "clusterIP same",
			a: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
			},
			b: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
			},
			expected: true,
		},
		{
			name: "clusterIP different",
			a: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
			},
			b: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.2"),
				},
			},
			expected: false,
		},
		{
			name: "ipv4 mapping present vs nil",
			a: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
			},
			b:        &Config{},
			expected: false,
		},
		{
			name: "ipv6 mapping same",
			a: &Config{
				IPv6Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("fd7a:115c:a1e0::1"),
					ClusterIP:          netip.MustParseAddr("2001:db8::1"),
				},
			},
			b: &Config{
				IPv6Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("fd7a:115c:a1e0::1"),
					ClusterIP:          netip.MustParseAddr("2001:db8::1"),
				},
			},
			expected: true,
		},
		{
			name: "dual stack same",
			a: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
				IPv6Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("fd7a:115c:a1e0::1"),
					ClusterIP:          netip.MustParseAddr("2001:db8::1"),
				},
			},
			b: &Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
				IPv6Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("fd7a:115c:a1e0::1"),
					ClusterIP:          netip.MustParseAddr("2001:db8::1"),
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.EqualIgnoringResolved(tt.b)
			if got != tt.expected {
				t.Errorf("EqualIgnoringResolved() = %v, want %v", got, tt.expected)
			}
			// Test symmetry
			got2 := tt.b.EqualIgnoringResolved(tt.a)
			if got2 != tt.expected {
				t.Errorf("EqualIgnoringResolved() (reversed) = %v, want %v", got2, tt.expected)
			}
		})
	}
}

func TestConfigIsExternalName(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		expected bool
	}{
		{
			name:     "empty config",
			cfg:      Config{},
			expected: false,
		},
		{
			name: "clusterIP config",
			cfg: Config{
				IPv4Mapping: &Mapping{
					TailscaleServiceIP: netip.MustParseAddr("100.64.0.1"),
					ClusterIP:          netip.MustParseAddr("10.0.0.1"),
				},
			},
			expected: false,
		},
		{
			name: "externalName config",
			cfg: Config{
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.IsExternalName()
			if got != tt.expected {
				t.Errorf("IsExternalName() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfigDNSRefreshNeeded(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		cfg      *Config
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "non-ExternalName config",
			cfg:      &Config{IPv4Mapping: &Mapping{}},
			expected: false,
		},
		{
			name: "ExternalName with zero LastDNSRefresh",
			cfg: &Config{
				ExternalName:   "example.com",
				LastDNSRefresh: 0,
			},
			expected: true,
		},
		{
			name: "ExternalName with recent LastDNSRefresh",
			cfg: &Config{
				ExternalName:   "example.com",
				LastDNSRefresh: now.Unix(),
			},
			expected: false,
		},
		{
			name: "ExternalName with old LastDNSRefresh",
			cfg: &Config{
				ExternalName:   "example.com",
				LastDNSRefresh: now.Add(-15 * time.Minute).Unix(),
			},
			expected: true,
		},
		{
			name: "ExternalName at exactly refresh interval",
			cfg: &Config{
				ExternalName:   "example.com",
				LastDNSRefresh: now.Add(-DNSRefreshInterval).Unix(),
			},
			expected: true,
		},
		{
			name: "ExternalName just before refresh interval",
			cfg: &Config{
				ExternalName:   "example.com",
				LastDNSRefresh: now.Add(-DNSRefreshInterval + time.Second).Unix(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.DNSRefreshNeeded(now)
			if got != tt.expected {
				t.Errorf("DNSRefreshNeeded() = %v, want %v", got, tt.expected)
			}
		})
	}
}
