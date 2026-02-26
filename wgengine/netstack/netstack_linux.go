// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	setAmbientCapsRaw = func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: []uintptr{unix.CAP_NET_RAW},
		}
	}
}
