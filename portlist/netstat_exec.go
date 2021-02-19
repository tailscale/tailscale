// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows freebsd openbsd darwin,go1.16 darwin,!go1.16,!arm64
// +build !ios

package portlist

import (
	"fmt"
	"os/exec"
	"strings"
)

var osHideWindow func(*exec.Cmd) // non-nil on Windows; see portlist_windows.go

// hideWindow returns c. On Windows it first sets SysProcAttr.HideWindow.
func hideWindow(c *exec.Cmd) *exec.Cmd {
	if osHideWindow != nil {
		osHideWindow(c)
	}
	return c
}

func listPortsNetstat(arg string) (List, error) {
	exe, err := exec.LookPath("netstat")
	if err != nil {
		return nil, fmt.Errorf("netstat: lookup: %v", err)
	}
	output, err := hideWindow(exec.Command(exe, arg)).Output()
	if err != nil {
		xe, ok := err.(*exec.ExitError)
		stderr := ""
		if ok {
			stderr = strings.TrimSpace(string(xe.Stderr))
		}
		return nil, fmt.Errorf("netstat: %v (%q)", err, stderr)
	}

	return parsePortsNetstat(string(output)), nil
}
