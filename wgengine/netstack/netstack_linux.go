// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
