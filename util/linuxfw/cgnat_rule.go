// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// CGNATRuleVerdict describes what action to take for a CGNAT firewall rule.
type CGNATRuleVerdict string

const (
	CGNATRuleVerdictDrop   CGNATRuleVerdict = "drop"
	CGNATRuleVerdictAccept CGNATRuleVerdict = "accept"
)

// CGNATRuleChain describes which base chain(s) a CGNAT firewall rule applies to.
type CGNATRuleChain string

const (
	CGNATRuleChainInput   CGNATRuleChain = "input"
	CGNATRuleChainForward CGNATRuleChain = "forward"
	CGNATRuleChainBoth    CGNATRuleChain = "both"
)

// CGNATRule is a Linux firewall base rule for CGNAT source matching.
type CGNATRule struct {
	Prefix  netip.Prefix
	Verdict CGNATRuleVerdict
	Chain   CGNATRuleChain
}

func cgnatRulesOrDefault(rules []CGNATRule) []CGNATRule {
	if len(rules) != 0 {
		return rules
	}
	return []CGNATRule{{
		Prefix:  tsaddr.CGNATRange(),
		Verdict: CGNATRuleVerdictDrop,
		Chain:   CGNATRuleChainBoth,
	}}
}

func cgnatRuleAppliesToInput(chain CGNATRuleChain) bool {
	return chain == CGNATRuleChainBoth || chain == CGNATRuleChainInput
}

func cgnatRuleAppliesToForward(chain CGNATRuleChain) bool {
	return chain == CGNATRuleChainBoth || chain == CGNATRuleChainForward
}
