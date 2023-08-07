// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tstun

import "tailscale.com/envknob"

// There are several kinds of MTU.
//
// On-the-wire MTU: This what the network device advertises as the
// maximum packet size available above the physical link layer. This
// includes IP headers and everything at a higher level. For Ethernet,
// this is typically 1500 bytes but can be larger or smaller.
//
// Tailscale interface MTU: This is what we advertise to userspace as
// the largest possible packet it can send through the tailscale
// interface. This is 80 bytes lower than the largest interface we
// have available to send things on, which is the size of the headers
// Wireguard adds (80 for IPv6, 60 for IPv4, but we don't know which
// it will be so we always subtract 80). E.g. if the largest interface
// MTU is 1500, we set the tailscale interface MTU to 1420.
//
// Peer MTU: The MTU that we have probed for the path to a specific
// peer's various endpoints. If this is smaller than the advertised
// tailscale interface, and the packet is larger than the peer MTU,
// then we generate ICMP Packet Too Big (IPv6) or Fragmentation Needed
// (IPv4) packets inside tailscale and drop the packet.
//
// Historically, we set the tailscale interface MTU to 1280. This
// means we treated the "on the wire" MTU as 1360. This is now the
// "Safe" value we use when we do not know what the path MTU is.
//
// Internally, we store the peer MTU as the MTU advertised to the user.
//
// We have to call these by different names or it is way way too confusing.
//
// Wire MTU
// User MTU
// Peer MTU
//
// What should happen when we set TS_DEBUG_MTU? It should set the
// interface to that, but we should not assume that the path MTU is
// this. So distinguish between what we set the interface MTU to and
// what we assume the path MTU is in the absence of probe information.

const (
	maxMTU            uint32 = 65536
	wireguardOverhead        = 80
	DefaultUserMTU    uint32 = 1280
	DefaultWireMTU    uint32 = 1280 + wireguardOverhead
)

func userMTUToWireMTU(userMTU uint32) uint32 {
	return userMTU + wireguardOverhead
}

func wireMTUToUserMTU(wireMTU uint32) uint32 {
	if wireMTU < wireguardOverhead {
		return 0
	}
	return wireMTU - wireguardOverhead
}

// TunMTU returns either the constant default user MTU of 1280, or the
// value set in TS_DEBUG_MTU clamped to a maximum of 65536.
func TunMTU() uint32 {
	// TunMTU is the Tailscale default MTU for now.
	//
	// wireguard-go defaults to 1420 bytes, which only works if the
	// "outer" MTU is 1500 bytes. This breaks on DSL connections
	// (typically 1492 MTU) and on GCE (1460 MTU?!).
	//
	// 1280 is the smallest MTU allowed for IPv6, which is a sensible
	// "probably works everywhere" setting until we develop proper PMTU
	// discovery.
	tunMTU := DefaultUserMTU
	if mtu, ok := envknob.LookupUintSized("TS_DEBUG_MTU", 10, 32); ok {
		mtu := uint32(mtu)
		if mtu > maxMTU {
			mtu = maxMTU
		}
		tunMTU = mtu
	}
	return tunMTU
}
