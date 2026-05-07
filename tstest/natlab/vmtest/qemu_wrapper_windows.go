// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"os"
	"os/exec"
)

// Stubs for Windows: no parent-death watcher, no process-group kill.
// The test still launches QEMU; cleanup just kills the single process.

func killWithParent(cmd *exec.Cmd) (*os.File, error) {
	return os.Open(os.DevNull)
}

func killProcessTree(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
