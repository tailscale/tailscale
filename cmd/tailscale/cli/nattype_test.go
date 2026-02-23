// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/net/netcheck"
	"tailscale.com/types/opt"
)

func TestClassifyNATType(t *testing.T) {
	tests := []struct {
		name    string
		report  *netcheck.Report
		localV4 netip.Addr
		want    string
	}{
		{
			name: "nil-report",
			want: natTypeUDPBlocked,
		},
		{
			name:   "udp-blocked",
			report: &netcheck.Report{UDP: false},
			want:   natTypeUDPBlocked,
		},
		{
			name: "no-nat",
			report: &netcheck.Report{
				UDP:      true,
				GlobalV4: netip.MustParseAddrPort("203.0.113.4:1234"),
			},
			localV4: netip.MustParseAddr("203.0.113.4"),
			want:    natTypeNoNAT,
		},
		{
			name: "address-and-port-dependent",
			report: &netcheck.Report{
				UDP:                   true,
				MappingVariesByDestIP: opt.NewBool(true),
			},
			want: natTypeAddressAndPortDependentMapping,
		},
		{
			name: "endpoint-independent",
			report: &netcheck.Report{
				UDP:                   true,
				MappingVariesByDestIP: opt.NewBool(false),
			},
			want: natTypeEndpointIndependentMapping,
		},
		{
			name: "address-dependent-fallback",
			report: &netcheck.Report{
				UDP: true,
			},
			want: natTypeAddressDependentMapping,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyNATType(tt.report, tt.localV4); got != tt.want {
				t.Fatalf("classifyNATType = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestFormatOptionalBool(t *testing.T) {
	tests := []struct {
		name string
		in   opt.Bool
		want string
	}{
		{"true", opt.NewBool(true), "true"},
		{"false", opt.NewBool(false), "false"},
		{"unset", opt.Bool(""), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatOptionalBool(tt.in); got != tt.want {
				t.Fatalf("formatOptionalBool = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestNATTypeSummaryForMappingVariation(t *testing.T) {
	gotSummary := natTypeSummaryFor(natTypeAddressAndPortDependentMapping)
	if !strings.Contains(gotSummary, "Expect more relay usage") {
		t.Fatalf("summary should set user expectation; got: %q", gotSummary)
	}

	report := &netcheck.Report{
		UDP:                   true,
		MappingVariesByDestIP: opt.NewBool(true),
		GlobalV4Counters: map[netip.AddrPort]int{
			netip.MustParseAddrPort("71.231.39.108:50309"): 23,
			netip.MustParseAddrPort("154.47.24.194:62782"): 1,
		},
	}
	gotDetails := natTypeTechnicalDetailsFor(natTypeAddressAndPortDependentMapping, report, netip.MustParseAddr("192.168.1.33"), "None")
	if !strings.Contains(gotDetails, "Observed 2 external IPv4 endpoint(s)") {
		t.Fatalf("technical details missing endpoint evidence: %q", gotDetails)
	}
	if !strings.Contains(gotDetails, "No UPnP/NAT-PMP/PCP assistance was detected.") {
		t.Fatalf("technical details missing port-mapping explanation: %q", gotDetails)
	}
}
