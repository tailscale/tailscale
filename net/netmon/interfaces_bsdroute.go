// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// FreeBSD and OpenBSD routing table functions.

//go:build freebsd || openbsd

package netmon

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

func getDelegatedInterface(ifIndex int) (int, error) {
	return 0, nil
}
