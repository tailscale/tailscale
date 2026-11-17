// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package integration

import (
	"os"
	"os/exec"
)

// setNewProcessGroup is a no-op; only Windows needs its own process group.
func setNewProcessGroup(cmd *exec.Cmd) {}

func interruptProcess(process *os.Process) error {
	return process.Signal(os.Interrupt)
}
