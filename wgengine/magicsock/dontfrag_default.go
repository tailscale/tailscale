// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux && !darwin) || android || ios

package magicsock

import (
	"errors"

	"tailscale.com/types/nettype"
)

// setDontFragment sets the dontfragment sockopt on pconn on the platforms that support it,
// for both IPv4 and IPv6.
// (C.f. https://datatracker.ietf.org/doc/html/rfc3542#section-11.2 for IPv6 fragmentation)
func setDontFragment(pconn nettype.PacketConn, network string) (err error) {
	return errors.New("setting don't fragment bit not supported on this OS")
}

// CanPMTUD returns whether this platform supports performing peet path MTU discovery.
func CanPMTUD() bool {
	return false
}
