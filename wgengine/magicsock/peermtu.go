// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (darwin && !ios) || (linux && !android)

package magicsock

import (
	"errors"

	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/net/tstun"
)

// Peer path MTU routines shared by platforms that implement it.

// DontFragSetting returns true if at least one of the underlying sockets of
// this connection is a UDP socket with the don't fragment bit set, otherwise it
// returns false. It also returns an error if either connection returned an error
// other than errUnsupportedConnType.
func (c *Conn) DontFragSetting() (bool, error) {
	df4, err4 := c.getDontFragment("udp4")
	df6, err6 := c.getDontFragment("udp6")
	df := df4 || df6
	err := err4
	if err4 != nil && err4 != errUnsupportedConnType {
		err = err6
	}
	if err == errUnsupportedConnType {
		err = nil
	}
	return df, err
}

// ShouldPMTUD returns true if this client should try to enable peer MTU
// discovery, false otherwise.
func (c *Conn) ShouldPMTUD() bool {
	if v, ok := debugEnablePMTUD().Get(); ok {
		if debugPMTUD() {
			c.logf("magicsock: peermtu: peer path MTU discovery set via envknob to %v", v)
		}
		return v
	}
	if c.controlKnobs != nil {
		if v := c.controlKnobs.PeerMTUEnable.Load(); v {
			if debugPMTUD() {
				c.logf("magicsock: peermtu: peer path MTU discovery enabled by control")
			}
			return v
		}
	}
	if debugPMTUD() {
		c.logf("magicsock: peermtu: peer path MTU discovery set by default to false")
	}
	return false // Until we feel confident PMTUD is solid.
}

// PeerMTUEnabled reports whether peer path MTU discovery is enabled.
func (c *Conn) PeerMTUEnabled() bool {
	return c.peerMTUEnabled.Load()
}

// UpdatePMTUD configures the underlying sockets of this Conn to enable or disable
// peer path MTU discovery according to the current configuration.
//
// Enabling or disabling peer path MTU discovery requires setting the don't
// fragment bit on its two underlying pconns. There are three distinct results
// for this operation on each pconn:
//
// 1. Success
// 2. Failure (not supported on this platform, or supported but failed)
// 3. Not a UDP socket (most likely one of IPv4 or IPv6 couldn't be used)
//
// To simplify the fast path for the most common case, we set the PMTUD status
// of the overall Conn according to the results of setting the sockopt on pconn
// as follows:
//
// 1. Both setsockopts succeed: PMTUD status update succeeds
// 2. One succeeds, one returns not a UDP socket: PMTUD status update succeeds
// 4. Neither setsockopt succeeds: PMTUD disabled
// 3. Either setsockopt fails: PMTUD disabled
//
// If the PMTUD settings changed, it resets the endpoint state so that it will
// re-probe path MTUs to this peer.
func (c *Conn) UpdatePMTUD() {
	if debugPMTUD() {
		df4, err4 := c.getDontFragment("udp4")
		df6, err6 := c.getDontFragment("udp6")
		c.logf("magicsock: peermtu: peer MTU status %v DF bit status: v4: %v (%v) v6: %v (%v)", c.peerMTUEnabled.Load(), df4, err4, df6, err6)
	}

	enable := c.ShouldPMTUD()
	if c.peerMTUEnabled.Load() == enable {
		c.logf("[v1] magicsock: peermtu: peer MTU status is %v", enable)
		return
	}

	newStatus := enable
	err4 := c.setDontFragment("udp4", enable)
	err6 := c.setDontFragment("udp6", enable)
	anySuccess := err4 == nil || err6 == nil
	noFailures := (err4 == nil || err4 == errUnsupportedConnType) && (err6 == nil || err6 == errUnsupportedConnType)

	if anySuccess && noFailures {
		c.logf("magicsock: peermtu: peer MTU status updated to %v", newStatus)
	} else {
		c.logf("[unexpected] magicsock: peermtu: updating peer MTU status to %v failed (v4: %v, v6: %v), disabling", enable, err4, err6)
		_ = c.setDontFragment("udp4", false)
		_ = c.setDontFragment("udp6", false)
		newStatus = false
	}
	if debugPMTUD() {
		c.logf("magicsock: peermtu: peer MTU probes are %v", tstun.WireMTUsToProbe)
	}
	c.peerMTUEnabled.Store(newStatus)
	c.resetEndpointStates()
}

var errEMSGSIZE error = unix.EMSGSIZE

func pmtuShouldLogDiscoTxErr(m disco.Message, err error) bool {
	// Large disco.Ping packets used to probe path MTU may result in
	// an EMSGSIZE error fairly regularly which can pollute logs.
	p, ok := m.(*disco.Ping)
	if !ok || p.Padding == 0 || !errors.Is(err, errEMSGSIZE) || debugPMTUD() {
		return true
	}
	return false
}
