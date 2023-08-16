// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"tailscale.com/envknob"
)

// The MTU (Maximum Transmission Unit) of a network interface is the
// largest packet that can be sent or received through that interface,
// including all headers above the link layer (e.g. IP headers, UDP
// headers, Wireguard headers, etc.). We have to think about several
// different values of MTU:
//
// Wire MTU: The MTU of an interface underneath the tailscale TUN,
// e.g. an Ethernet network card will default to a 1500 byte MTU. The
// user may change this MTU at any time.
//
// TUN MTU: The current MTU of the tailscale TUN. This MTU is adjusted
// downward to make room for the wireguard/tailscale headers. For
// example, if the underlying network interface's MTU is 1500 bytes,
// the maximum size of a packet entering the tailscale TUN is 1420
// bytes. The user may change this MTU at any time via the OS's tools
// (ifconfig, ip, etc.).
//
// User configured initial MTU: The MTU the tailscale TUN should be
// created with, set by the user via TS_DEBUG_MTU. It should be
// adjusted down from the underlying interface MTU by 80 bytes to make
// room for the wireguard headers. This envknob is mostly for
// debugging. This value is used once at TUN creation and ignored
// thereafter.
//
// User configured current MTU: The MTU set via the OS's tools
// (ifconfig, ip, etc.). This MTU can change at any time. Setting the
// MTU this way goes through the MTU() method of tailscale's TUN
// wrapper.
//
// Maximum probed MTU: This is the largest MTU size that we send probe
// packets for.
//
// Safe MTU: If the tailscale TUN MTU is set to this value, almost all
// packets will get to their destination. Tailscale defaults to this
// MTU in the absence of path MTU probe information or user MTU
// configuration. We may occasionally find a path that needs a smaller
// MTU but it is very rare.
//
// Peer MTU: This is the path MTU to a peer's current best
// endpoint. It defaults to the Safe MTU unless we have path MTU probe
// results that tell us otherwise.
//
// Initial MTU: This is the MTU tailscaled creates the TUN with. In
// order of priority, it is:
//
// 1. If set, the value of TS_DEBUG_MTU clamped to a maximum of 65536
// 2. If TS_DEBUG_PMTUD is set, the maximum size MTU we probe, minus wg overhead
// 3. If TS_DEBUG_PMTUD is not set, the Safe MTU
//
// Current MTU: This the MTU of the tailscale TUN at any given moment
// after TUN creation. In order of priority, it is:
//
// 1. The MTU set by the user via the OS, if it has ever been set
// 2. If TS_DEBUG_PMTUD is set, the maximum size MTU we probe, minus wg overhead
// 4. If TS_DEBUG_PMTUD is not set, the Safe MTU

// TunMTU is used to describe MTUs for the tailscale TUN, while
// WireMTU is used to describe MTUs for the underlying network
// devices.
type TunMTU uint32
type WireMTU uint32

const (
	// Largest MTU we will consider for the Tailscale TUN.
	maxTunMTU TunMTU = TunMTU(MaxPacketSize)
	// A default "safe" MTU for the Tailscale TUN that we can use
	// in the absence of other information such as path MTU probes.
	safeTunMTU TunMTU = 1280
)

// WireMTUsToProbe are the MTUs we are most likely to see in real world
// networks. These are used to send discovery pings in packets padded
// to exactly match the goal MTU.
//
// XXX Review these before committing
var WireMTUsToProbe = [...]WireMTU{
	576,  // Smallest MTU for IPv4, probably useless?
	1124, // An observed MTU in the wild, maybe 1100 instead?
	1280, // Smallest MTU allowed for IPv6, current default
	1480, // A little less than most common MTU, for tunnels or such
	1500, // Most common real world MTU
	8000, // Some jumbo frames are this size
	9000, // Most jumbo frames are this size or larger
}

// MaxProbedWireMTU is the largest MTU we will test for path MTU
// discovery.
var MaxProbedWireMTU WireMTU

func init() {
	for _, m := range WireMTUsToProbe {
		if m > MaxProbedWireMTU {
			MaxProbedWireMTU = m
		}
	}
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

// TunToWireMTU converts the MTU that the Tailscale TUN presents to
// the user to the on-the-wire MTU necessary to transmit a packet of
// TUN MTU bytes plus the Tailscale/Wireguard overhead.
func TunToWireMTU(t TunMTU) WireMTU {
	return WireMTU(t + wgHeaderLen)
}

// WireToTunMTU converts the on-the-wire MTU to the Tailscale MTU
// necessary to transmit a packet of TUN MTU bytes plus the
// Tailscale/Wireguard overhead.
func WireToTunMTU(w WireMTU) TunMTU {
	if w < wgHeaderLen {
		return 0
	}
	return TunMTU(w - wgHeaderLen)
}

// DefaultTunMTU returns the MTU we use to set the Tailscale TUN
// MTU. It is also the path MTU that we default to if we have no
// information about the path to a peer.
//
// 1. If set, the value of TS_DEBUG_MTU clamped to a maximum of MaxTunMTU
// 2. If TS_DEBUG_PMTUD is set, the maximum size MTU we probe, minus wg overhead
// 3. If TS_DEBUG_PMTUD is not set, the Safe MTU
func DefaultTunMTU() TunMTU {
	if m, ok := envknob.LookupUintSized("TS_DEBUG_MTU", 10, 32); ok {
		debugMTU := TunMTU(m)
		if debugMTU > maxTunMTU {
			debugMTU = maxTunMTU
		}
		return debugMTU
	}

	debugPMTUD, _ := envknob.LookupBool("TS_DEBUG_PMTUD")
	if debugPMTUD == true {
		return WireToTunMTU(MaxProbedWireMTU)
	}

	return safeTunMTU
}

// DefaultWireMTU returns the default TUN MTU, adjusted for wireguard
// overhead.
func DefaultWireMTU() WireMTU {
	return TunToWireMTU(DefaultTunMTU())
}
