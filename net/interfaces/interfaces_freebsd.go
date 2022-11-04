// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This might work on other BSDs, but only tested on FreeBSD.

//go:build freebsd

package interfaces

import (
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// fetchRoutingTable calls route.FetchRIB, fetching NET_RT_DUMP.
func fetchRoutingTable() (rib []byte, err error) {
	return route.FetchRIB(syscall.AF_UNSPEC, unix.NET_RT_DUMP, 0)
}

func parseRoutingTable(rib []byte) ([]route.Message, error) {
	return route.ParseRIB(syscall.NET_RT_IFLIST, rib)
}
