// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"testing"
)

func newFakeIPTablesRunner() *iptablesRunner {
	return NewFakeIPTablesRunner().(*iptablesRunner)
}

func Test_iptablesRunner_EnsurePortMapRuleForSvc(t *testing.T) {
	v4Addr := netip.MustParseAddr("10.0.0.4")
	v6Addr := netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	testPM := PortMap{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}
	testPM2 := PortMap{Protocol: "udp", MatchPort: 4004, TargetPort: 53}
	v4Rule := argsForPortMapRule("test-svc", "tailscale0", v4Addr, testPM)
	tests := []struct {
		name              string
		targetIP          netip.Addr
		svc               string
		pm                PortMap
		precreateSvcRules [][]string
	}{
		{
			name:     "pm_for_ipv4",
			targetIP: v4Addr,
			svc:      "test-svc",
			pm:       testPM,
		},
		{
			name:     "pm_for_ipv6",
			targetIP: v6Addr,
			svc:      "test-svc-2",
			pm:       testPM2,
		},
		{
			name:              "add_existing_rule",
			targetIP:          v4Addr,
			svc:               "test-svc",
			pm:                testPM,
			precreateSvcRules: [][]string{v4Rule},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptr := newFakeIPTablesRunner()
			table := iptr.getIPTByAddr(tt.targetIP)
			for _, ruleset := range tt.precreateSvcRules {
				mustPrecreatePortMapRule(t, ruleset, table)
			}
			if err := iptr.EnsurePortMapRuleForSvc(tt.svc, "tailscale0", tt.targetIP, tt.pm); err != nil {
				t.Errorf("[unexpected error] iptablesRunner.EnsurePortMapRuleForSvc() = %v", err)
			}
			args := argsForPortMapRule(tt.svc, "tailscale0", tt.targetIP, tt.pm)
			exists, err := table.Exists("nat", "PREROUTING", args...)
			if err != nil {
				t.Fatalf("error checking if rule exists: %v", err)
			}
			if !exists {
				t.Errorf("expected rule was not created")
			}
		})
	}
}

func Test_iptablesRunner_DeletePortMapRuleForSvc(t *testing.T) {
	v4Addr := netip.MustParseAddr("10.0.0.4")
	v6Addr := netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	testPM := PortMap{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}
	v4Rule := argsForPortMapRule("test", "tailscale0", v4Addr, testPM)
	v6Rule := argsForPortMapRule("test", "tailscale0", v6Addr, testPM)

	tests := []struct {
		name              string
		targetIP          netip.Addr
		svc               string
		pm                PortMap
		precreateSvcRules [][]string
	}{
		{
			name:              "multiple_rules_ipv4_deleted",
			targetIP:          v4Addr,
			svc:               "test",
			pm:                testPM,
			precreateSvcRules: [][]string{v4Rule, v6Rule},
		},
		{
			name:              "multiple_rules_ipv6_deleted",
			targetIP:          v6Addr,
			svc:               "test",
			pm:                testPM,
			precreateSvcRules: [][]string{v4Rule, v6Rule},
		},
		{
			name:              "non-existent_rule_deleted",
			targetIP:          v4Addr,
			svc:               "test",
			pm:                testPM,
			precreateSvcRules: [][]string{v6Rule},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptr := newFakeIPTablesRunner()
			table := iptr.getIPTByAddr(tt.targetIP)
			for _, ruleset := range tt.precreateSvcRules {
				mustPrecreatePortMapRule(t, ruleset, table)
			}
			if err := iptr.DeletePortMapRuleForSvc(tt.svc, "tailscale0", tt.targetIP, tt.pm); err != nil {
				t.Errorf("iptablesRunner.DeletePortMapRuleForSvc() errored: %v ", err)
			}
			deletedRule := argsForPortMapRule(tt.svc, "tailscale0", tt.targetIP, tt.pm)
			exists, err := table.Exists("nat", "PREROUTING", deletedRule...)
			if err != nil {
				t.Fatalf("error verifying that rule does not exist after deletion: %v", err)
			}
			if exists {
				t.Errorf("portmap rule exists after deletion")
			}
		})
	}
}

func Test_iptablesRunner_DeleteSvc(t *testing.T) {
	v4Addr := netip.MustParseAddr("10.0.0.4")
	v6Addr := netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	testPM := PortMap{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}
	iptr := newFakeIPTablesRunner()

	// create two rules that will consitute svc1
	s1R1 := argsForPortMapRule("svc1", "tailscale0", v4Addr, testPM)
	mustPrecreatePortMapRule(t, s1R1, iptr.getIPTByAddr(v4Addr))
	s1R2 := argsForPortMapRule("svc1", "tailscale0", v6Addr, testPM)
	mustPrecreatePortMapRule(t, s1R2, iptr.getIPTByAddr(v6Addr))

	// create two rules that will consitute svc2
	s2R1 := argsForPortMapRule("svc2", "tailscale0", v4Addr, testPM)
	mustPrecreatePortMapRule(t, s2R1, iptr.getIPTByAddr(v4Addr))
	s2R2 := argsForPortMapRule("svc2", "tailscale0", v6Addr, testPM)
	mustPrecreatePortMapRule(t, s2R2, iptr.getIPTByAddr(v6Addr))

	// delete svc1
	if err := iptr.DeleteSvc("svc1", "tailscale0", []netip.Addr{v4Addr, v6Addr}, []PortMap{testPM}); err != nil {
		t.Fatalf("error deleting service: %v", err)
	}

	// validate that svc1 no longer exists
	svcMustNotExist(t, "svc1", map[string][]string{v4Addr.String(): s1R1, v6Addr.String(): s1R2}, iptr)

	// validate that svc2 still exists
	svcMustExist(t, "svc2", map[string][]string{v4Addr.String(): s2R1, v6Addr.String(): s2R2}, iptr)
}

func Test_iptablesRunner_EnsureDNATRuleForSvc(t *testing.T) {
	v4OrigDst := netip.MustParseAddr("10.0.0.1")
	v4Target := netip.MustParseAddr("10.0.0.2")
	v6OrigDst := netip.MustParseAddr("fd7a:115c:a1e0::1")
	v6Target := netip.MustParseAddr("fd7a:115c:a1e0::2")
	v4Rule := argsForIngressRule("svc:test", v4OrigDst, v4Target)

	tests := []struct {
		name              string
		svcName           string
		origDst           netip.Addr
		targetIP          netip.Addr
		precreateSvcRules [][]string
	}{
		{
			name:     "dnat_for_ipv4",
			svcName:  "svc:test",
			origDst:  v4OrigDst,
			targetIP: v4Target,
		},
		{
			name:     "dnat_for_ipv6",
			svcName:  "svc:test-2",
			origDst:  v6OrigDst,
			targetIP: v6Target,
		},
		{
			name:              "add_existing_rule",
			svcName:           "svc:test",
			origDst:           v4OrigDst,
			targetIP:          v4Target,
			precreateSvcRules: [][]string{v4Rule},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptr := newFakeIPTablesRunner()
			table := iptr.getIPTByAddr(tt.targetIP)
			for _, ruleset := range tt.precreateSvcRules {
				mustPrecreateDNATRule(t, ruleset, table)
			}
			if err := iptr.EnsureDNATRuleForSvc(tt.svcName, tt.origDst, tt.targetIP); err != nil {
				t.Errorf("[unexpected error] iptablesRunner.EnsureDNATRuleForSvc() = %v", err)
			}
			args := argsForIngressRule(tt.svcName, tt.origDst, tt.targetIP)
			exists, err := table.Exists("nat", "PREROUTING", args...)
			if err != nil {
				t.Fatalf("error checking if rule exists: %v", err)
			}
			if !exists {
				t.Errorf("expected rule was not created")
			}
		})
	}
}

func Test_iptablesRunner_DeleteDNATRuleForSvc(t *testing.T) {
	v4OrigDst := netip.MustParseAddr("10.0.0.1")
	v4Target := netip.MustParseAddr("10.0.0.2")
	v6OrigDst := netip.MustParseAddr("fd7a:115c:a1e0::1")
	v6Target := netip.MustParseAddr("fd7a:115c:a1e0::2")
	v4Rule := argsForIngressRule("svc:test", v4OrigDst, v4Target)
	v6Rule := argsForIngressRule("svc:test", v6OrigDst, v6Target)

	tests := []struct {
		name              string
		svcName           string
		origDst           netip.Addr
		targetIP          netip.Addr
		precreateSvcRules [][]string
	}{
		{
			name:              "multiple_rules_ipv4_deleted",
			svcName:           "svc:test",
			origDst:           v4OrigDst,
			targetIP:          v4Target,
			precreateSvcRules: [][]string{v4Rule, v6Rule},
		},
		{
			name:              "multiple_rules_ipv6_deleted",
			svcName:           "svc:test",
			origDst:           v6OrigDst,
			targetIP:          v6Target,
			precreateSvcRules: [][]string{v4Rule, v6Rule},
		},
		{
			name:              "non-existent_rule_deleted",
			svcName:           "svc:test",
			origDst:           v4OrigDst,
			targetIP:          v4Target,
			precreateSvcRules: [][]string{v6Rule},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptr := newFakeIPTablesRunner()
			table := iptr.getIPTByAddr(tt.targetIP)
			for _, ruleset := range tt.precreateSvcRules {
				mustPrecreateDNATRule(t, ruleset, table)
			}
			if err := iptr.DeleteDNATRuleForSvc(tt.svcName, tt.origDst, tt.targetIP); err != nil {
				t.Errorf("iptablesRunner.DeleteDNATRuleForSvc() errored: %v ", err)
			}
			deletedRule := argsForIngressRule(tt.svcName, tt.origDst, tt.targetIP)
			exists, err := table.Exists("nat", "PREROUTING", deletedRule...)
			if err != nil {
				t.Fatalf("error verifying that rule does not exist after deletion: %v", err)
			}
			if exists {
				t.Errorf("DNAT rule exists after deletion")
			}
		})
	}
}

func mustPrecreateDNATRule(t *testing.T, rules []string, table iptablesInterface) {
	t.Helper()
	exists, err := table.Exists("nat", "PREROUTING", rules...)
	if err != nil {
		t.Fatalf("error ensuring that nat PREROUTING table exists: %v", err)
	}
	if exists {
		return
	}
	if err := table.Append("nat", "PREROUTING", rules...); err != nil {
		t.Fatalf("error precreating DNAT rule: %v", err)
	}
}

func svcMustExist(t *testing.T, svcName string, rules map[string][]string, iptr *iptablesRunner) {
	t.Helper()
	for dst, ruleset := range rules {
		tip := netip.MustParseAddr(dst)
		exists, err := iptr.getIPTByAddr(tip).Exists("nat", "PREROUTING", ruleset...)
		if err != nil {
			t.Fatalf("error checking whether %s exists: %v", svcName, err)
		}
		if !exists {
			t.Fatalf("service %s should be deleted,but found rule for %s", svcName, dst)
		}
	}
}

func svcMustNotExist(t *testing.T, svcName string, rules map[string][]string, iptr *iptablesRunner) {
	t.Helper()
	for dst, ruleset := range rules {
		tip := netip.MustParseAddr(dst)
		exists, err := iptr.getIPTByAddr(tip).Exists("nat", "PREROUTING", ruleset...)
		if err != nil {
			t.Fatalf("error checking whether %s exists: %v", svcName, err)
		}
		if exists {
			t.Fatalf("service %s should exist, but rule for %s is missing", svcName, dst)
		}
	}
}

func mustPrecreatePortMapRule(t *testing.T, rules []string, table iptablesInterface) {
	t.Helper()
	exists, err := table.Exists("nat", "PREROUTING", rules...)
	if err != nil {
		t.Fatalf("error ensuring that nat PREROUTING table exists: %v", err)
	}
	if exists {
		return
	}
	if err := table.Append("nat", "PREROUTING", rules...); err != nil {
		t.Fatalf("error precreating portmap rule: %v", err)
	}
}
