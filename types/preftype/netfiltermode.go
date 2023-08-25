// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package preftype is a leaf package containing types for various
// preferences.
package preftype

// NetfilterMode is the firewall management mode to use when
// programming the Linux network stack.
type NetfilterMode int

// These numbers are persisted to disk in JSON files and thus can't be
// renumbered or repurposed.
const (
	NetfilterOff              NetfilterMode = 0 // remove all tailscale netfilter state
	NetfilterIPTablesNoDivert NetfilterMode = 1 // manage tailscale IPTables chains, but don't call them
	NetfilterIPTablesOn       NetfilterMode = 2 // manage tailscale IPTables chains and call them from main chains
	NetfilterNFTablesNoDivert NetfilterMode = 3 // manage tailscale nftables chains, but don't call them
	NetfilterNFTablesOn       NetfilterMode = 4 // manage tailscale nftables chains and call them from conventional tables
	NetfilterAutoNoDivert     NetfilterMode = 5 // manage chains in the mode that best fits the system, but don't call them
	NetfilterAutoOn           NetfilterMode = 6 // manage chains in the mode that best fits the system, and call them from the main/conventional chains
)

func (m NetfilterMode) String() string {
	switch m {
	case NetfilterOff:
		return "off"
	case NetfilterIPTablesNoDivert:
		return "nodivert(iptables)"
	case NetfilterIPTablesOn:
		return "on(iptables)"
	case NetfilterNFTablesNoDivert:
		return "nodivert(nftables)"
	case NetfilterNFTablesOn:
		return "on(nftables)"
	case NetfilterAutoNoDivert:
		return "nodivert(auto)"
	case NetfilterAutoOn:
		return "on(auto)"
	default:
		return "???"
	}
}
