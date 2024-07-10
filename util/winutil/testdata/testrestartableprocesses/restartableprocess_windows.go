// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The testrestartableprocesses is a program for a test.
package main

import (
	"golang.org/x/sys/windows"
)

func init() {
	register("RestartableProcess", RestartableProcess)
}

func RestartableProcess() {
	windows.SleepEx(windows.INFINITE, false)
}
