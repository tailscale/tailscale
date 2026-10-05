// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package sparse contains some helpful generic sparse file functions.
package sparse

import (
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func punchAt(fd *os.File, off, size int64) error {
	if err := syscall.Fallocate(int(fd.Fd()), unix.FALLOC_FL_KEEP_SIZE|unix.FALLOC_FL_PUNCH_HOLE, off, size); err != nil {
		return &fs.PathError{Op: "fallocate", Path: fd.Name(), Err: err}
	}
	return nil
}
