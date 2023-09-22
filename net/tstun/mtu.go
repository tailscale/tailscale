// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tstun

import "tailscale.com/envknob"

const (
	maxMTU     uint32 = 65536
	defaultMTU uint32 = 1280
)

// DefaultMTU returns either the constant default MTU of 1280, or the value set
// in TS_DEBUG_MTU clamped to a maximum of 65536.
func DefaultMTU() uint32 {
	// DefaultMTU is the Tailscale default MTU for now.
	//
	// wireguard-go defaults to 1420 bytes, which only works if the
	// "outer" MTU is 1500 bytes. This breaks on DSL connections
	// (typically 1492 MTU) and on GCE (1460 MTU?!).
	//
	// 1280 is the smallest MTU allowed for IPv6, which is a sensible
	// "probably works everywhere" setting until we develop proper PMTU
	// discovery.
	tunMTU := defaultMTU
	if mtu, ok := envknob.LookupUintSized("TS_DEBUG_MTU", 10, 32); ok {
		mtu := uint32(mtu)
		if mtu > maxMTU {
			mtu = maxMTU
		}
		tunMTU = mtu
	}
	return tunMTU
}
