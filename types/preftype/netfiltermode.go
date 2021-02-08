// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package preftype is a leaf package containing types for various
// preferences.
package preftype

// NetfilterMode is the firewall management mode to use when
// programming the Linux network stack.
type NetfilterMode int

const (
	NetfilterOff      NetfilterMode = iota // remove all tailscale netfilter state
	NetfilterNoDivert                      // manage tailscale chains, but don't call them
	NetfilterOn                            // manage tailscale chains and call them from main chains
)

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
