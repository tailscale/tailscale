// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package magicsock

import (
	"golang.org/x/sys/unix"
)

// dontFrag{Enabled,Disabled} are the values of the don't fragment sockopt.
const (
	dontFragEnabled  = 1
	dontFragDisabled = 0
)

func getDontFragOpt(network string) int {
	if network == "udp4" {
		return unix.IP_DONTFRAG
	}
	return unix.IPV6_DONTFRAG
}
