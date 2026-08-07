// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package integration

import (
	"errors"
	"os"
	"os/exec"
)

// Non-Windows stubs for the peer process helpers; their callers are Windows-only.

func setNewProcessGroup(cmd *exec.Cmd) {}

func gracefulStop(process *os.Process) error {
	return errors.New("CTRL_BREAK is only supported on Windows")
}
