// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"fmt"
	"net/netip"
)

// This file contains functionality to insert portmapping rules for a 'service'.
// These are currently only used by the Kubernetes operator proxies.
// An iptables rule for such a service contains a comment with the service name.

// EnsurePortMapRuleForSvc adds a prerouting rule that forwards traffic received
// on match port and NOT on the provided interface to target IP and target port.
// Rule will only be added if it does not already exists.
func (i *iptablesRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	table := i.getIPTByAddr(targetIP)
	args := argsForPortMapRule(svc, tun, targetIP, pm)
	exists, err := table.Exists("nat", "PREROUTING", args...)
	if err != nil {
		return fmt.Errorf("error checking if rule exists: %w", err)
	}
	if !exists {
		return table.Append("nat", "PREROUTING", args...)
	}
	return nil
}

// DeleteMapRuleForSvc constructs a prerouting rule as would be created by
// EnsurePortMapRuleForSvc with the provided args and, if such a rule exists,
// deletes it.
func (i *iptablesRunner) DeletePortMapRuleForSvc(svc, excludeI string, targetIP netip.Addr, pm PortMap) error {
	table := i.getIPTByAddr(targetIP)
	args := argsForPortMapRule(svc, excludeI, targetIP, pm)
	exists, err := table.Exists("nat", "PREROUTING", args...)
	if err != nil {
		return fmt.Errorf("error checking if rule exists: %w", err)
	}
	if exists {
		return table.Delete("nat", "PREROUTING", args...)
	}
	return nil
}

// DeleteSvc constructs all possible rules that would have been created by
// EnsurePortMapRuleForSvc from the provided args and ensures that each one that
// exists is deleted.
func (i *iptablesRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pms []PortMap) error {
	for _, tip := range targetIPs {
		for _, pm := range pms {
			if err := i.DeletePortMapRuleForSvc(svc, tun, tip, pm); err != nil {
				return fmt.Errorf("error deleting rule: %w", err)
			}
		}
	}
	return nil
}

func argsForPortMapRule(svc, excludeI string, targetIP netip.Addr, pm PortMap) []string {
	c := commentForSvc(svc, pm)
	return []string{
		"!", "-i", excludeI,
		"-p", pm.Protocol,
		"--dport", fmt.Sprintf("%d", pm.MatchPort),
		"-m", "comment", "--comment", c,
		"-j", "DNAT",
		"--to-destination", fmt.Sprintf("%v:%v", targetIP, pm.TargetPort),
	}
}

// commentForSvc generates a comment to be added to an iptables DNAT rule for a
// service. This is for iptables debugging/readability purposes only.
func commentForSvc(svc string, pm PortMap) string {
	return fmt.Sprintf("%s:%s:%d -> %s:%d", svc, pm.Protocol, pm.MatchPort, pm.Protocol, pm.TargetPort)
}
