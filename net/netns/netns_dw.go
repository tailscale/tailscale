// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || windows

package netns

import (
	"errors"
	"net"
	"net/netip"
)

var errUnspecifiedHost = errors.New("unspecified host")

func parseAddress(address string) (addr netip.Addr, err error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = address
	}
	if host == "" {
		return addr, errUnspecifiedHost
	}

	return netip.ParseAddr(host)
}

func UseSocketMark() bool {
	return false
}
