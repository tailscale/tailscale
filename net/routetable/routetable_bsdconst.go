// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build freebsd || openbsd

package routetable

import "golang.org/x/sys/unix"

const (
	ribType        = unix.NET_RT_DUMP
	parseType      = unix.NET_RT_IFLIST
	rmExpectedType = unix.RTM_GET

	// Nothing to skip
	skipFlags = 0
)

var flags = map[int]string{
	unix.RTF_BLACKHOLE: "blackhole",
	unix.RTF_BROADCAST: "broadcast",
	unix.RTF_GATEWAY:   "gateway",
	unix.RTF_HOST:      "host",
	unix.RTF_LOCAL:     "local",
	unix.RTF_MULTICAST: "multicast",
	unix.RTF_REJECT:    "reject",
	unix.RTF_STATIC:    "static",
	unix.RTF_UP:        "up",
}
