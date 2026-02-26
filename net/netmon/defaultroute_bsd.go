// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Common code for FreeBSD and OpenBSD.
// Not used on iOS or macOS. See defaultroute_darwin.go.

//go:build freebsd || openbsd

package netmon

import "net"

func defaultRoute() (d DefaultRouteDetails, err error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return d, err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return d, err
	}
	d.InterfaceName = iface.Name
	d.InterfaceIndex = idx
	return d, nil
}
