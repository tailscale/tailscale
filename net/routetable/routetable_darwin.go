// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin
// +build darwin

package routetable

import "golang.org/x/sys/unix"

const (
	ribType        = unix.NET_RT_DUMP2
	parseType      = unix.NET_RT_IFLIST2
	rmExpectedType = unix.RTM_GET2

	// Skip routes that were cloned from a parent
	skipFlags = unix.RTF_WASCLONED
)

var flags = map[int]string{
	unix.RTF_BLACKHOLE: "blackhole",
	unix.RTF_BROADCAST: "broadcast",
	unix.RTF_GATEWAY:   "gateway",
	unix.RTF_GLOBAL:    "global",
	unix.RTF_HOST:      "host",
	unix.RTF_IFSCOPE:   "ifscope",
	unix.RTF_MULTICAST: "multicast",
	unix.RTF_REJECT:    "reject",
	unix.RTF_ROUTER:    "router",
	unix.RTF_STATIC:    "static",
	unix.RTF_UP:        "up",
}
