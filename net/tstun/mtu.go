// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"tailscale.com/envknob"
)

// The MTU (Maximum Transmission Unit) of a network interface is the largest
// packet that can be sent or received through that interface, including all
// headers above the link layer (e.g. IP headers, UDP headers, Wireguard
// headers, etc.). We have to think about several different values of MTU:
//
// Wire MTU: The MTU of an interface underneath the tailscale TUN, e.g. an
// Ethernet network card will default to a 1500 byte MTU. The user may change
// this MTU at any time.
//
// TUN MTU: The current MTU of the tailscale TUN. This MTU is adjusted downward
// to make room for the wireguard/tailscale headers. For example, if the
// underlying network interface's MTU is 1500 bytes, the maximum size of a
// packet entering the tailscale TUN is 1420 bytes. The user may change this MTU
// at any time via the OS's tools (ifconfig, ip, etc.).
//
// User configured initial MTU: The MTU the tailscale TUN should be created
// with, set by the user via TS_DEBUG_MTU. It should be adjusted down from the
// underlying interface MTU by 80 bytes to make room for the wireguard
// headers. This envknob is mostly for debugging. This value is used once at TUN
// creation and ignored thereafter.
//
// User configured current MTU: The MTU set via the OS's tools (ifconfig, ip,
// etc.). This MTU can change at any time. Setting the MTU this way goes through
// the MTU() method of tailscale's TUN wrapper.
//
// Maximum probed MTU: This is the largest MTU size that we send probe packets
// for.
//
// Safe MTU: If the tailscale TUN MTU is set to this value, almost all packets
// will get to their destination. Tailscale defaults to this MTU in the absence
// of path MTU probe information or user MTU configuration. We may occasionally
// find a path that needs a smaller MTU but it is very rare.
//
// Peer MTU: This is the path MTU to a peer's current best endpoint. It defaults
// to the Safe MTU unless we have path MTU probe results that tell us otherwise.
//
// Initial MTU: This is the MTU tailscaled creates the TUN with. In order of
// priority, it is:
//
// 1. If set, the value of TS_DEBUG_MTU clamped to a maximum of 65536
// 2. If TS_DEBUG_ENABLE_PMTUD is set, the maximum size MTU we probe, minus wg
//    overhead
// 3. If TS_DEBUG_ENABLE_PMTUD is not set, the Safe MTU
//
// Current MTU: This the MTU of the tailscale TUN at any given moment
// after TUN creation. In order of priority, it is:
//
// 1. The MTU set by the user via the OS, if it has ever been set
// 2. If TS_DEBUG_ENABLE_PMTUD is set, the maximum size MTU we probe, minus wg
//    overhead
// 4. If TS_DEBUG_ENABLE_PMTUD is not set, the Safe MTU

// TUNMTU is the MTU for the tailscale TUN.
type TUNMTU uint32

// WireMTU is the MTU for the underlying network devices.
type WireMTU uint32

const (
	// maxTUNMTU is the largest MTU we will consider for the Tailscale
	// TUN. This is inherited from wireguard-go and can be surprisingly
	// small; on Windows it is currently 2048 - 32 bytes and iOS it is 1700
	// - 32 bytes.
	// TODO(val,raggi): On Windows this seems to derive from RIO driver
	// constraints in Wireguard but we don't use RIO so could probably make
	// this bigger.
	maxTUNMTU TUNMTU = TUNMTU(MaxPacketSize)
	// safeTUNMTU is the default "safe" MTU for the Tailscale TUN that we
	// use in the absence of other information such as path MTU probes.
	safeTUNMTU TUNMTU = 1280
)

// WireMTUsToProbe is a list of the on-the-wire MTUs we want to probe. Each time
// magicsock discovery begins, it will send a set of pings, one of each size
// listed below.
var WireMTUsToProbe = []WireMTU{
	WireMTU(safeTUNMTU),      // Tailscale over Tailscale :)
	TUNToWireMTU(safeTUNMTU), // Smallest MTU allowed for IPv6, current default
	1400,                     // Most common MTU minus a few bytes for tunnels
	1500,                     // Most common MTU
	8000,                     // Should fit inside all jumbo frame sizes
	9000,                     // Most jumbo frames are this size or larger
}

// wgHeaderLen is the length of all the headers Wireguard adds to a packet
// in the worst case (IPv6). This constant is for use when we can't or
// shouldn't use information about the IP version of a specific packet
// (e.g., calculating the MTU for the Tailscale interface.
//
// A Wireguard header includes:
//
// - 20-byte IPv4 header or 40-byte IPv6 header
// - 8-byte UDP header
// - 4-byte type
// - 4-byte key index
// - 8-byte nonce
// - 16-byte authentication tag
const wgHeaderLen = 40 + 8 + 4 + 4 + 8 + 16

// TUNToWireMTU takes the MTU that the Tailscale TUN presents to the user and
// returns the on-the-wire MTU necessary to transmit the largest packet that
// will fit through the TUN, given that we have to add wireguard headers.
func TUNToWireMTU(t TUNMTU) WireMTU {
	return WireMTU(t + wgHeaderLen)
}

// WireToTUNMTU takes the MTU of an underlying network device and returns the
// largest possible MTU for a Tailscale TUN operating on top of that device,
// given that we have to add wireguard headers.
func WireToTUNMTU(w WireMTU) TUNMTU {
	if w < wgHeaderLen {
		return 0
	}
	return TUNMTU(w - wgHeaderLen)
}

// DefaultTUNMTU returns the MTU we use to set the Tailscale TUN
// MTU. It is also the path MTU that we default to if we have no
// information about the path to a peer.
//
// 1. If set, the value of TS_DEBUG_MTU clamped to a maximum of MaxTUNMTU
// 2. If TS_DEBUG_ENABLE_PMTUD is set, the maximum size MTU we probe, minus wg overhead
// 3. If TS_DEBUG_ENABLE_PMTUD is not set, the Safe MTU
func DefaultTUNMTU() TUNMTU {
	if m, ok := envknob.LookupUintSized("TS_DEBUG_MTU", 10, 32); ok {
		return min(TUNMTU(m), maxTUNMTU)
	}

	debugPMTUD, _ := envknob.LookupBool("TS_DEBUG_ENABLE_PMTUD")
	if debugPMTUD {
		// TODO: While we are just probing MTU but not generating PTB,
		// this has to continue to return the safe MTU. When we add the
		// code to generate PTB, this will be:
		//
		// return WireToTUNMTU(maxProbedWireMTU)
		return safeTUNMTU
	}

	return safeTUNMTU
}

// SafeWireMTU returns the wire MTU that is safe to use if we have no
// information about the path MTU to this peer.
func SafeWireMTU() WireMTU {
	return TUNToWireMTU(safeTUNMTU)
}

// DefaultWireMTU returns the default TUN MTU, adjusted for wireguard
// overhead.
func DefaultWireMTU() WireMTU {
	return TUNToWireMTU(DefaultTUNMTU())
}
