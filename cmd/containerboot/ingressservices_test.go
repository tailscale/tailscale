// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"net/netip"
	"testing"

	"tailscale.com/kube/ingressservices"
	"tailscale.com/util/linuxfw"
)

func TestSyncIngressConfigs(t *testing.T) {
	tests := []struct {
		name           string
		currentConfigs *ingressservices.Configs
		currentStatus  *ingressservices.Status
		wantServices   map[string]struct {
			TailscaleServiceIP netip.Addr
			ClusterIP          netip.Addr
		}
	}{
		{
			name: "add_new_rules_when_no_existing_config",
			currentConfigs: &ingressservices.Configs{
				"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
			},
			currentStatus: nil,
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:foo": makeWantService("100.64.0.1", "10.0.0.1"),
			},
		},
		{
			name: "add_multiple_services",
			currentConfigs: &ingressservices.Configs{
				"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
				"svc:bar": makeServiceConfig("100.64.0.2", "10.0.0.2", "", ""),
				"svc:baz": makeServiceConfig("100.64.0.3", "10.0.0.3", "", ""),
			},
			currentStatus: nil,
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:foo": makeWantService("100.64.0.1", "10.0.0.1"),
				"svc:bar": makeWantService("100.64.0.2", "10.0.0.2"),
				"svc:baz": makeWantService("100.64.0.3", "10.0.0.3"),
			},
		},
		{
			name: "add_both_ipv4_and_ipv6_rules",
			currentConfigs: &ingressservices.Configs{
				"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.1", "2001:db8::1", "2001:db8::2"),
			},
			currentStatus: nil,
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:foo": makeWantService("2001:db8::1", "2001:db8::2"),
			},
		},
		{
			name: "add_ipv6_only_rules",
			currentConfigs: &ingressservices.Configs{
				"svc:ipv6": makeServiceConfig("", "", "2001:db8::10", "2001:db8::20"),
			},
			currentStatus: nil,
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:ipv6": makeWantService("2001:db8::10", "2001:db8::20"),
			},
		},
		{
			name:           "delete_all_rules_when_config_removed",
			currentConfigs: nil,
			currentStatus: &ingressservices.Status{
				Configs: ingressservices.Configs{
					"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
					"svc:bar": makeServiceConfig("100.64.0.2", "10.0.0.2", "", ""),
				},
				PodIPv4: "10.0.0.2",    // Current pod IPv4
				PodIPv6: "2001:db8::2", // Current pod IPv6
			},
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{},
		},
		{
			name: "add_remove_modify",
			currentConfigs: &ingressservices.Configs{
				"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.2", "", ""), // Changed cluster IP
				"svc:new": makeServiceConfig("100.64.0.4", "10.0.0.4", "", ""),
			},
			currentStatus: &ingressservices.Status{
				Configs: ingressservices.Configs{
					"svc:foo": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
					"svc:bar": makeServiceConfig("100.64.0.2", "10.0.0.2", "", ""),
					"svc:baz": makeServiceConfig("100.64.0.3", "10.0.0.3", "", ""),
				},
				PodIPv4: "10.0.0.2",    // Current pod IPv4
				PodIPv6: "2001:db8::2", // Current pod IPv6
			},
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:foo": makeWantService("100.64.0.1", "10.0.0.2"),
				"svc:new": makeWantService("100.64.0.4", "10.0.0.4"),
			},
		},
		{
			name: "update_with_outdated_status",
			currentConfigs: &ingressservices.Configs{
				"svc:web": makeServiceConfig("100.64.0.10", "10.0.0.10", "", ""),
				"svc:web-ipv6": {
					IPv6Mapping: &ingressservices.Mapping{
						TailscaleServiceIP: netip.MustParseAddr("2001:db8::10"),
						ClusterIP:          netip.MustParseAddr("2001:db8::20"),
					},
				},
				"svc:api": makeServiceConfig("100.64.0.20", "10.0.0.20", "", ""),
			},
			currentStatus: &ingressservices.Status{
				Configs: ingressservices.Configs{
					"svc:web": makeServiceConfig("100.64.0.10", "10.0.0.10", "", ""),
					"svc:web-ipv6": {
						IPv6Mapping: &ingressservices.Mapping{
							TailscaleServiceIP: netip.MustParseAddr("2001:db8::10"),
							ClusterIP:          netip.MustParseAddr("2001:db8::20"),
						},
					},
					"svc:old": makeServiceConfig("100.64.0.30", "10.0.0.30", "", ""),
				},
				PodIPv4: "10.0.0.1",    // Outdated pod IP
				PodIPv6: "2001:db8::1", // Outdated pod IP
			},
			wantServices: map[string]struct {
				TailscaleServiceIP netip.Addr
				ClusterIP          netip.Addr
			}{
				"svc:web":      makeWantService("100.64.0.10", "10.0.0.10"),
				"svc:web-ipv6": makeWantService("2001:db8::10", "2001:db8::20"),
				"svc:api":      makeWantService("100.64.0.20", "10.0.0.20"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nfr linuxfw.NetfilterRunner = linuxfw.NewFakeNetfilterRunner()

			ep := &ingressProxy{
				nfr:     nfr,
				podIPv4: "10.0.0.2",    // Current pod IPv4
				podIPv6: "2001:db8::2", // Current pod IPv6
			}

			err := ep.syncIngressConfigs(tt.currentConfigs, tt.currentStatus)
			if err != nil {
				t.Fatalf("syncIngressConfigs failed: %v", err)
			}

			fake := nfr.(*linuxfw.FakeNetfilterRunner)
			gotServices := fake.GetServiceState()
			if len(gotServices) != len(tt.wantServices) {
				t.Errorf("got %d services, want %d", len(gotServices), len(tt.wantServices))
			}
			for svc, want := range tt.wantServices {
				got, ok := gotServices[svc]
				if !ok {
					t.Errorf("service %s not found", svc)
					continue
				}
				if got.TailscaleServiceIP != want.TailscaleServiceIP {
					t.Errorf("service %s: got TailscaleServiceIP %v, want %v", svc, got.TailscaleServiceIP, want.TailscaleServiceIP)
				}
				if got.ClusterIP != want.ClusterIP {
					t.Errorf("service %s: got ClusterIP %v, want %v", svc, got.ClusterIP, want.ClusterIP)
				}
			}
		})
	}
}

func makeServiceConfig(tsIP, clusterIP string, tsIP6, clusterIP6 string) ingressservices.Config {
	cfg := ingressservices.Config{}
	if tsIP != "" && clusterIP != "" {
		cfg.IPv4Mapping = &ingressservices.Mapping{
			TailscaleServiceIP: netip.MustParseAddr(tsIP),
			ClusterIP:          netip.MustParseAddr(clusterIP),
		}
	}
	if tsIP6 != "" && clusterIP6 != "" {
		cfg.IPv6Mapping = &ingressservices.Mapping{
			TailscaleServiceIP: netip.MustParseAddr(tsIP6),
			ClusterIP:          netip.MustParseAddr(clusterIP6),
		}
	}
	return cfg
}

func makeWantService(tsIP, clusterIP string) struct {
	TailscaleServiceIP netip.Addr
	ClusterIP          netip.Addr
} {
	return struct {
		TailscaleServiceIP netip.Addr
		ClusterIP          netip.Addr
	}{
		TailscaleServiceIP: netip.MustParseAddr(tsIP),
		ClusterIP:          netip.MustParseAddr(clusterIP),
	}
}
