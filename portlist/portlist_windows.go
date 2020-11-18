// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Forking on Windows is insanely expensive, so don't do it too often.
const pollInterval = 5 * time.Second

func listPorts() (List, error) {
	return listPortsNetstat("-na")
}

func addProcesses(pl []Port) ([]Port, error) {
	if t := windows.GetCurrentProcessToken(); !t.IsElevated() {
		return listPortsNetstat("-na")
	}
	return listPortsNetstat("-nab")
}

func init() {
	osHideWindow = func(c *exec.Cmd) {
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}
}
