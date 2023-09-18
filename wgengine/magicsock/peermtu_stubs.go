// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux && !darwin) || android || ios

package magicsock

import (
	"errors"
)

// setDontFragment sets the don't fragment sockopt on the underlying connection
// specified by network, which must be "udp4" or "udp6". See
// https://datatracker.ietf.org/doc/html/rfc3542#section-11.2 for details on
// IPv6 fragmentation.
//
// Return values:
// - an error if peer MTU is not supported on this OS
// - errNoActiveUDP if the underlying connection is not UDP
// - otherwise, the result of setting the don't fragment bit
func (c *Conn) setDontFragment(network string, enable bool) error {
	return errors.New("peer path MTU discovery not supported on this OS")
}

// getDontFragment gets the don't fragment setting on the underlying connection
// specified by network, which must be "udp4" or "udp6". Returns true if the
// underlying connection is UDP and the don't fragment bit is set, otherwise
// false.
func (c *Conn) getDontFragment(network string) (bool, error) {
	return false, nil
}

func (c *Conn) DontFragSetting() (bool, error) {
	return false, nil
}

func (c *Conn) ShouldPMTUD() bool {
	return false
}

func (c *Conn) PeerMTUEnabled() bool {
	return false
}

func (c *Conn) UpdatePMTUD() {
}
