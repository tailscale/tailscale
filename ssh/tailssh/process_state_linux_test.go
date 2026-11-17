// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// pidGone reports whether pid is absent or a zombie.
func pidGone(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return unix.Kill(pid, 0) == unix.ESRCH
	}
	// The comm field may contain spaces and parentheses.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return false
	}
	return b[i+2] == 'Z'
}
