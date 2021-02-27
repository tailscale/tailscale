// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

// Package winuntil contains misc Windows/win32 helper functions.
package winutil

import (
	"golang.org/x/sys/windows"
)

// GetDesktopPID searches the PID of the process that's running the
// currently active desktop and whether it was found.
// Usually the PID will be for explorer.exe.
func GetDesktopPID() (pid uint32, ok bool) {
	hwnd := windows.GetShellWindow()
	if hwnd == 0 {
		return 0, false
	}
	windows.GetWindowThreadProcessId(hwnd, &pid)
	return pid, pid != 0
}
