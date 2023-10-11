// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package preftype is a leaf package containing types for various
// preferences.
package preftype

import "fmt"

// NetfilterMode is the firewall management mode to use when
// programming the Linux network stack.
type NetfilterMode int

// These numbers are persisted to disk in JSON files and thus can't be
// renumbered or repurposed.
const (
	NetfilterOff      NetfilterMode = 0 // remove all tailscale netfilter state
	NetfilterNoDivert NetfilterMode = 1 // manage tailscale chains, but don't call them
	NetfilterOn       NetfilterMode = 2 // manage tailscale chains and call them from main chains
)

func ParseNetfilterMode(s string) (NetfilterMode, error) {
	switch s {
	case "off":
		return NetfilterOff, nil
	case "nodivert":
		return NetfilterNoDivert, nil
	case "on":
		return NetfilterOn, nil
	default:
		return NetfilterOff, fmt.Errorf("unknown netfilter mode %q", s)
	}
}

func (m NetfilterMode) String() string {
	switch m {
	case NetfilterOff:
		return "off"
	case NetfilterNoDivert:
		return "nodivert"
	case NetfilterOn:
		return "on"
	default:
		return "???"
	}
}
