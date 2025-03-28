// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !wasm && !plan9 && !tamago

package cli

import (
	"errors"
	"os"
	"syscall"
)

// Stats a path and returns the owning uid and gid. Errors on non-unix platforms.
func fileStat(f *os.File) (int, int, error) {
	if f == nil {
		return -1, -1, errors.New("file cannot be nil")
	}

	var stat syscall.Stat_t
	if err := syscall.Stat(f.Name(), &stat); err != nil {
		return -1, -1, err
	}

	return int(stat.Uid), int(stat.Gid), nil
}
