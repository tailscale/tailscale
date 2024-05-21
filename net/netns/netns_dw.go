// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || windows

package netns

import (
	"net"
	"net/netip"
)

func parseAddress(address string) (addr netip.Addr, err error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = address
	}

	return netip.ParseAddr(host)
}
