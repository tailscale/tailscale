// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"syscall"
)

// dontFrag{Enabled,Disabled} are the values of the don't fragment sockopt.
const (
	dontFragEnabled  = syscall.IP_PMTUDISC_DO
	dontFragDisabled = syscall.IP_PMTUDISC_DONT
)

func getDontFragOpt(network string) int {
	if network == "udp4" {
		return syscall.IP_MTU_DISCOVER
	}
	return syscall.IPV6_MTU_DISCOVER
}
