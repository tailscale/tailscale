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

func appendListeningPorts(base []Port) ([]Port, error) {
	// TODO(bradfitz): stop shelling out to netstat and use the
	// net/netstat package instead. When doing so, be sure to filter
	// out all of 127.0.0.0/8 and not just 127.0.0.1.
	return appendListeningPortsNetstat(base, "-na")
}

func addProcesses(pl []Port) ([]Port, error) {
	// OpenCurrentProcessToken instead of GetCurrentProcessToken,
	// as GetCurrentProcessToken only works on Windows 8+.
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	if !tok.IsElevated() {
		return appendListeningPortsNetstat(nil, "-na")
	}
	return appendListeningPortsNetstat(nil, "-nab")
}

func init() {
	osHideWindow = func(c *exec.Cmd) {
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}
}
