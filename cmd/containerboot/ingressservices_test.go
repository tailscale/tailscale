// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"net/netip"
	"testing"
	"time"

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

func TestAddDNATRulesForExternalName_NilConfig(t *testing.T) {
	nfr := linuxfw.NewFakeNetfilterRunner()
	err := addDNATRulesForExternalName(nfr, "svc:test", nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if err.Error() != "config is nil" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeleteDNATRulesForExternalName_NilConfig(t *testing.T) {
	nfr := linuxfw.NewFakeNetfilterRunner()
	err := deleteDNATRulesForExternalName(nfr, "svc:test", nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if err.Error() != "config is nil" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeleteDNATRulesForExternalName_NoResolvedIPs(t *testing.T) {
	nfr := linuxfw.NewFakeNetfilterRunner()
	cfg := &ingressservices.Config{
		ExternalName:         "example.com",
		TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
	}
	// Should not error, just log a warning
	err := deleteDNATRulesForExternalName(nfr, "svc:test", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteDNATRulesForExternalName_WithResolvedIPs(t *testing.T) {
	nfr := linuxfw.NewFakeNetfilterRunner()

	// First add rules manually to simulate existing state
	tsIPv4 := netip.MustParseAddr("100.64.0.1")
	destIPv4 := netip.MustParseAddr("93.184.216.34")
	if err := nfr.EnsureDNATRuleForSvc("svc:test", tsIPv4, destIPv4); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	// Verify rule exists
	state := nfr.GetServiceState()
	if len(state) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(state))
	}

	// Now delete using the ExternalName function
	cfg := &ingressservices.Config{
		ExternalName:         "example.com",
		TailscaleServiceIPv4: tsIPv4,
		ResolvedIPs:          []netip.Addr{destIPv4},
	}
	err := deleteDNATRulesForExternalName(nfr, "svc:test", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify rule was deleted
	state = nfr.GetServiceState()
	if len(state) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(state))
	}
}

func TestDeleteDNATRulesForExternalName_IPv6(t *testing.T) {
	nfr := linuxfw.NewFakeNetfilterRunner()

	tsIPv6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	destIPv6 := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
	if err := nfr.EnsureDNATRuleForSvc("svc:test", tsIPv6, destIPv6); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	cfg := &ingressservices.Config{
		ExternalName:         "example.com",
		TailscaleServiceIPv6: tsIPv6,
		ResolvedIPs:          []netip.Addr{destIPv6},
	}
	err := deleteDNATRulesForExternalName(nfr, "svc:test", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state := nfr.GetServiceState()
	if len(state) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(state))
	}
}

func TestGetRulesToAdd_ExternalNameStable(t *testing.T) {
	// Test that ExternalName services with ResolvedIPs in status
	// are not re-added when the config doesn't have ResolvedIPs
	// and DNS refresh is not needed.
	p := &ingressProxy{
		podIPv4: "10.0.0.1",
		podIPv6: "2001:db8::1",
	}

	cfgs := &ingressservices.Configs{
		"svc:external": {
			ExternalName:         "example.com",
			TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			// Note: no ResolvedIPs - this comes from the operator config
		},
	}

	status := &ingressservices.Status{
		Configs: ingressservices.Configs{
			"svc:external": {
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
				LastDNSRefresh:       time.Now().Unix(), // Recent refresh, no need to re-resolve
			},
		},
		PodIPv4: "10.0.0.1",
		PodIPv6: "2001:db8::1",
	}

	rulesToAdd := p.getRulesToAdd(cfgs, status)
	if len(rulesToAdd) != 0 {
		t.Errorf("expected no rules to add (ResolvedIPs should be ignored), got %d", len(rulesToAdd))
	}
}

func TestGetRulesToDelete_ExternalNameStable(t *testing.T) {
	// Test that ExternalName services with ResolvedIPs in status
	// are not deleted when the config doesn't have ResolvedIPs
	// and DNS refresh is not needed.
	p := &ingressProxy{
		podIPv4: "10.0.0.1",
		podIPv6: "2001:db8::1",
	}

	cfgs := &ingressservices.Configs{
		"svc:external": {
			ExternalName:         "example.com",
			TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
			// Note: no ResolvedIPs - this comes from the operator config
		},
	}

	status := &ingressservices.Status{
		Configs: ingressservices.Configs{
			"svc:external": {
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
				LastDNSRefresh:       time.Now().Unix(), // Recent refresh, no need to re-resolve
			},
		},
		PodIPv4: "10.0.0.1",
		PodIPv6: "2001:db8::1",
	}

	rulesToDelete := p.getRulesToDelete(cfgs, status)
	if len(rulesToDelete) != 0 {
		t.Errorf("expected no rules to delete (ResolvedIPs should be ignored), got %d", len(rulesToDelete))
	}
}

func TestGetRulesToAdd_ExternalNameConfigChanged(t *testing.T) {
	// Test that ExternalName services ARE re-added when actual config changes
	p := &ingressProxy{
		podIPv4: "10.0.0.1",
		podIPv6: "2001:db8::1",
	}

	cfgs := &ingressservices.Configs{
		"svc:external": {
			ExternalName:         "newhost.example.com", // Changed!
			TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
		},
	}

	status := &ingressservices.Status{
		Configs: ingressservices.Configs{
			"svc:external": {
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			},
		},
		PodIPv4: "10.0.0.1",
		PodIPv6: "2001:db8::1",
	}

	rulesToAdd := p.getRulesToAdd(cfgs, status)
	if len(rulesToAdd) != 1 {
		t.Errorf("expected 1 rule to add (ExternalName changed), got %d", len(rulesToAdd))
	}

	rulesToDelete := p.getRulesToDelete(cfgs, status)
	if len(rulesToDelete) != 1 {
		t.Errorf("expected 1 rule to delete (ExternalName changed), got %d", len(rulesToDelete))
	}
}

func TestGetRules_ExternalNameDNSRefreshNeeded(t *testing.T) {
	// Test that ExternalName services trigger re-resolution when DNS refresh interval has passed
	p := &ingressProxy{
		podIPv4: "10.0.0.1",
		podIPv6: "2001:db8::1",
	}

	cfgs := &ingressservices.Configs{
		"svc:external": {
			ExternalName:         "example.com",
			TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
		},
	}

	// LastDNSRefresh is old (more than 10 minutes ago)
	oldRefresh := time.Now().Add(-15 * time.Minute).Unix()
	status := &ingressservices.Status{
		Configs: ingressservices.Configs{
			"svc:external": {
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
				LastDNSRefresh:       oldRefresh,
			},
		},
		PodIPv4: "10.0.0.1",
		PodIPv6: "2001:db8::1",
	}

	// Should trigger re-add due to DNS refresh needed
	rulesToAdd := p.getRulesToAdd(cfgs, status)
	if len(rulesToAdd) != 1 {
		t.Errorf("expected 1 rule to add (DNS refresh needed), got %d", len(rulesToAdd))
	}

	// Should also trigger delete of old rules
	rulesToDelete := p.getRulesToDelete(cfgs, status)
	if len(rulesToDelete) != 1 {
		t.Errorf("expected 1 rule to delete (DNS refresh needed), got %d", len(rulesToDelete))
	}
}

func TestGetRules_ExternalNameNoDNSRefreshWithZeroTimestamp(t *testing.T) {
	// Test that ExternalName services with no LastDNSRefresh (zero value) trigger refresh
	p := &ingressProxy{
		podIPv4: "10.0.0.1",
		podIPv6: "2001:db8::1",
	}

	cfgs := &ingressservices.Configs{
		"svc:external": {
			ExternalName:         "example.com",
			TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
		},
	}

	// LastDNSRefresh is zero (never refreshed)
	status := &ingressservices.Status{
		Configs: ingressservices.Configs{
			"svc:external": {
				ExternalName:         "example.com",
				TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
				LastDNSRefresh:       0, // Never refreshed
			},
		},
		PodIPv4: "10.0.0.1",
		PodIPv6: "2001:db8::1",
	}

	// Should trigger re-add due to DNS refresh needed
	rulesToAdd := p.getRulesToAdd(cfgs, status)
	if len(rulesToAdd) != 1 {
		t.Errorf("expected 1 rule to add (DNS refresh needed for zero timestamp), got %d", len(rulesToAdd))
	}
}

func TestIngressServicesStatusIsEqual(t *testing.T) {
	tests := []struct {
		name     string
		st       *ingressservices.Configs
		st1      *ingressservices.Configs
		expected bool
	}{
		{
			name:     "both nil",
			st:       nil,
			st1:      nil,
			expected: true,
		},
		{
			name:     "first nil",
			st:       nil,
			st1:      &ingressservices.Configs{},
			expected: false,
		},
		{
			name:     "same configs",
			st:       &ingressservices.Configs{"svc:a": makeServiceConfig("100.64.0.1", "10.0.0.1", "", "")},
			st1:      &ingressservices.Configs{"svc:a": makeServiceConfig("100.64.0.1", "10.0.0.1", "", "")},
			expected: true,
		},
		{
			name: "different ResolvedIPs ignored",
			st: &ingressservices.Configs{
				"svc:a": {
					ExternalName:         "example.com",
					TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
				},
			},
			st1: &ingressservices.Configs{
				"svc:a": {
					ExternalName:         "example.com",
					TailscaleServiceIPv4: netip.MustParseAddr("100.64.0.1"),
					ResolvedIPs:          []netip.Addr{netip.MustParseAddr("93.184.216.34")},
				},
			},
			expected: true,
		},
		{
			name: "different length",
			st: &ingressservices.Configs{
				"svc:a": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
			},
			st1: &ingressservices.Configs{
				"svc:a": makeServiceConfig("100.64.0.1", "10.0.0.1", "", ""),
				"svc:b": makeServiceConfig("100.64.0.2", "10.0.0.2", "", ""),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ingressServicesStatusIsEqual(tt.st, tt.st1)
			if got != tt.expected {
				t.Errorf("ingressServicesStatusIsEqual() = %v, want %v", got, tt.expected)
			}
		})
	}
}
