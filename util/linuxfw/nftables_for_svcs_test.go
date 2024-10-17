// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
)

// This test creates a temporary network namespace for the nftables rules being
// set up, so it needs to run in a privileged mode. Locally it needs to be run
// by root, else it will be silently skipped. In CI it runs in a privileged
// container.
func Test_nftablesRunner_EnsurePortMapRuleForSvc(t *testing.T) {
	conn := newSysConn(t)
	runner := newFakeNftablesRunnerWithConn(t, conn, true)
	ipv4, ipv6 := netip.MustParseAddr("100.99.99.99"), netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	pmTCP := PortMap{MatchPort: 4003, TargetPort: 80, Protocol: "TCP"}
	pmTCP1 := PortMap{MatchPort: 4004, TargetPort: 443, Protocol: "TCP"}

	// Create a rule for service 'foo' to forward TCP traffic to IPv4 endpoint
	runner.EnsurePortMapRuleForSvc("foo", "tailscale0", ipv4, pmTCP)
	svcChains(t, 1, conn)
	chainRuleCount(t, "foo", 1, conn, nftables.TableFamilyIPv4)
	checkPortMapRule(t, "foo", ipv4, pmTCP, runner, nftables.TableFamilyIPv4)

	// Create another rule for service 'foo' to forward TCP traffic to the
	// same IPv4 endpoint, but to a different port.
	runner.EnsurePortMapRuleForSvc("foo", "tailscale0", ipv4, pmTCP1)
	svcChains(t, 1, conn)
	chainRuleCount(t, "foo", 2, conn, nftables.TableFamilyIPv4)
	checkPortMapRule(t, "foo", ipv4, pmTCP1, runner, nftables.TableFamilyIPv4)

	// Create a rule for service 'foo' to forward TCP traffic to an IPv6 endpoint
	runner.EnsurePortMapRuleForSvc("foo", "tailscale0", ipv6, pmTCP)
	svcChains(t, 2, conn)
	chainRuleCount(t, "foo", 1, conn, nftables.TableFamilyIPv6)
	checkPortMapRule(t, "foo", ipv6, pmTCP, runner, nftables.TableFamilyIPv6)

	// Create a rule for service 'bar' to forward TCP traffic to IPv4 endpoint
	runner.EnsurePortMapRuleForSvc("bar", "tailscale0", ipv4, pmTCP)
	svcChains(t, 3, conn)
	chainRuleCount(t, "bar", 1, conn, nftables.TableFamilyIPv4)
	checkPortMapRule(t, "bar", ipv4, pmTCP, runner, nftables.TableFamilyIPv4)

	// Create a rule for service 'bar' to forward TCP traffic to an IPv6 endpoint
	runner.EnsurePortMapRuleForSvc("bar", "tailscale0", ipv6, pmTCP)
	svcChains(t, 4, conn)
	chainRuleCount(t, "bar", 1, conn, nftables.TableFamilyIPv6)
	checkPortMapRule(t, "bar", ipv6, pmTCP, runner, nftables.TableFamilyIPv6)

	// Delete service bar
	runner.DeleteSvc("bar", "tailscale0", []netip.Addr{ipv4, ipv6}, []PortMap{pmTCP})
	svcChains(t, 2, conn)

	// Delete a rule from service foo
	runner.DeletePortMapRuleForSvc("foo", "tailscale0", ipv4, pmTCP)
	svcChains(t, 2, conn)
	chainRuleCount(t, "foo", 1, conn, nftables.TableFamilyIPv4)

	// Delete service foo
	runner.DeleteSvc("foo", "tailscale0", []netip.Addr{ipv4, ipv6}, []PortMap{pmTCP, pmTCP1})
	svcChains(t, 0, conn)
}

// svcChains verifies that the expected number of chains exist (for either IP
// family) and that each of them is configured as NAT prerouting chain.
func svcChains(t *testing.T, wantCount int, conn *nftables.Conn) {
	t.Helper()
	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("error listing chains: %v", err)
	}
	if len(chains) != wantCount {
		t.Fatalf("wants %d chains, got %d", wantCount, len(chains))
	}
	for _, ch := range chains {
		if *ch.Policy != nftables.ChainPolicyAccept {
			t.Fatalf("chain %s has unexpected policy %v", ch.Name, *ch.Policy)
		}
		if ch.Type != nftables.ChainTypeNAT {
			t.Fatalf("chain %s has unexpected type %v", ch.Name, ch.Type)
		}
		if *ch.Hooknum != *nftables.ChainHookPrerouting {
			t.Fatalf("chain %s is attached to unexpected hook %v", ch.Name, ch.Hooknum)
		}
		if *ch.Priority != *nftables.ChainPriorityNATDest {
			t.Fatalf("chain %s has unexpected priority %v", ch.Name, ch.Priority)
		}
	}
}

// chainRuleCount verifies that the named chain in the given table contains the provided number of rules.
func chainRuleCount(t *testing.T, name string, numOfRules int, conn *nftables.Conn, fam nftables.TableFamily) {
	t.Helper()
	chains, err := conn.ListChainsOfTableFamily(fam)
	if err != nil {
		t.Fatalf("error listing chains: %v", err)
	}

	for _, ch := range chains {
		if ch.Name == name {
			checkChainRules(t, conn, ch, numOfRules)
			return
		}
	}
	t.Fatalf("chain %s does not exist", name)
}

// checkPortMapRule verifies that rule for the provided target IP and PortMap exists in a chain identified by service
// name and IP family.
func checkPortMapRule(t *testing.T, svc string, targetIP netip.Addr, pm PortMap, runner *nftablesRunner, fam nftables.TableFamily) {
	t.Helper()
	chains, err := runner.conn.ListChainsOfTableFamily(fam)
	if err != nil {
		t.Fatalf("error listing chains: %v", err)
	}
	var chain *nftables.Chain
	for _, ch := range chains {
		if ch.Name == svc {
			chain = ch
			break
		}
	}
	if chain == nil {
		t.Fatalf("chain for service %s does not exist", svc)
	}
	meta := svcPortMapRuleMeta(svc, targetIP, pm)
	p, err := protoFromString(pm.Protocol)
	if err != nil {
		t.Fatalf("error converting protocol: %v", err)
	}
	wantsRule := portMapRule(chain.Table, chain, "tailscale0", targetIP, pm.MatchPort, pm.TargetPort, p, meta)
	checkRule(t, wantsRule, runner.conn)
}

// checkRule checks that the provided rules exists.
func checkRule(t *testing.T, rule *nftables.Rule, conn *nftables.Conn) {
	t.Helper()
	gotRule, err := findRule(conn, rule)
	if err != nil {
		t.Fatalf("error looking up rule: %v", err)
	}
	if gotRule == nil {
		t.Fatal("rule not found")
	}
}
