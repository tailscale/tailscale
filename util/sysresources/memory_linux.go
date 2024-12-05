// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sysresources

import "golang.org/x/sys/unix"

func totalMemoryImpl() uint64 {
	var info unix.Sysinfo_t

	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}

	// uint64 casts are required since these might be uint32s
	return uint64(info.Totalram) * uint64(info.Unit)
}
