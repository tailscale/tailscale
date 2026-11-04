// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bytes"
	"context"
	"log"
	"net/netip"
	"os"
	"strings"
	"testing"

	"tailscale.com/util/linuxfw"
)

// noIPv6NATRunner wraps a NetfilterRunner and reports that the host does not
// support IPv6 NAT.
type noIPv6NATRunner struct {
	linuxfw.NetfilterRunner
}

func (noIPv6NATRunner) HasIPV6NAT() bool { return false }

func TestInstallIngressForwardingRulesWarning(t *testing.T) {
	const warning = "https://github.com/tailscale/tailscale/issues/12156"

	v4 := netip.MustParseAddr("10.0.0.1")
	v6 := netip.MustParseAddr("fd00::1")
	tsV4 := netip.MustParsePrefix("100.64.0.1/32")
	tsV6 := netip.MustParsePrefix("fd7a:115c:a1e0::1/128")

	tests := []struct {
		name        string
		dsts        []netip.Addr
		tsIPs       []netip.Prefix
		noIPv6NAT   bool
		wantWarning bool
		wantErr     bool
	}{
		{
			name:  "v4_service_dual_stack_proxy",
			dsts:  []netip.Addr{v4},
			tsIPs: []netip.Prefix{tsV4, tsV6},
		},
		{
			// This is the case the warning was written for (#12156): the
			// proxy has an IPv4 tailnet address that clients can connect
			// to, but there is no IPv4 destination to forward to.
			name:        "v6_service_dual_stack_proxy",
			dsts:        []netip.Addr{v6},
			tsIPs:       []netip.Prefix{tsV4, tsV6},
			wantWarning: true,
		},
		{
			name:        "v6_service_dual_stack_proxy_v6_address_first",
			dsts:        []netip.Addr{v6},
			tsIPs:       []netip.Prefix{tsV6, tsV4},
			wantWarning: true,
		},
		{
			// The only destination cannot be served, so no rule is
			// installed and an error is returned.
			name:        "v6_service_v4_only_proxy",
			dsts:        []netip.Addr{v6},
			tsIPs:       []netip.Prefix{tsV4},
			wantWarning: true,
			wantErr:     true,
		},
		{
			name:  "v6_service_v6_only_proxy",
			dsts:  []netip.Addr{v6},
			tsIPs: []netip.Prefix{tsV6},
		},
		{
			name:  "dual_stack_service_dual_stack_proxy",
			dsts:  []netip.Addr{v4, v6},
			tsIPs: []netip.Prefix{tsV4, tsV6},
		},
		{
			// The IPv6 destination is skipped (the proxy has no IPv6
			// tailnet address), but the IPv4 one is still served.
			name:  "dual_stack_service_v4_only_proxy",
			dsts:  []netip.Addr{v4, v6},
			tsIPs: []netip.Prefix{tsV4},
		},
		{
			// The IPv6 destination is skipped (the host has no IPv6 NAT),
			// but the IPv4 one is still served.
			name:      "dual_stack_service_dual_stack_proxy_no_ipv6_nat",
			dsts:      []netip.Addr{v4, v6},
			tsIPs:     []netip.Prefix{tsV4, tsV6},
			noIPv6NAT: true,
		},
		{
			// The only destination cannot be served, so no rule is
			// installed and an error is returned.
			name:        "v6_service_dual_stack_proxy_no_ipv6_nat",
			dsts:        []netip.Addr{v6},
			tsIPs:       []netip.Prefix{tsV4, tsV6},
			noIPv6NAT:   true,
			wantWarning: true,
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			nfr := linuxfw.NewFakeIPTablesRunner()
			if tt.noIPv6NAT {
				nfr = noIPv6NATRunner{nfr}
			}
			err := installIngressForwardingRules(context.Background(), tt.dsts, tt.tsIPs, nfr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("installIngressForwardingRules() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := strings.Contains(buf.String(), warning); got != tt.wantWarning {
				t.Errorf("warning logged = %v, want %v; log output:\n%s", got, tt.wantWarning, buf.String())
			}
		})
	}
}
