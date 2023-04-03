// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build freebsd || openbsd || dragonfly || netbsd

package sysresources

import "golang.org/x/sys/unix"

func totalMemoryImpl() uint64 {
	val, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		return 0
	}
	return val
}
