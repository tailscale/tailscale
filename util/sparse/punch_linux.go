// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package sparse contains some helpful generic sparse file functions.
package sparse

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// punchAt for linux
func punchAt(fd *os.File, off, size int64) error {
	return syscall.Fallocate(int(fd.Fd()), unix.FALLOC_FL_KEEP_SIZE|unix.FALLOC_FL_PUNCH_HOLE, off, size)
}
