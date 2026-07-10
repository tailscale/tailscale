// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package integration

import (
	"testing"

	"tailscale.com/tstest"
)

// Issue 2137: make sure Windows tailscaled works with the CLI alone, without
// the GUI to kick off a Start. Runs tailscaled as a real Windows service via
// WindowsServiceMode; see NewTestEnv's Windows gating.
func TestOneNodeUpWindowsStyle(t *testing.T) {
	tstest.Parallel(t)
	env := NewTestEnv(t, WindowsServiceMode())
	n1 := NewTestNode(t, env)
	n1.upFlagGOOS = "windows"

	d1 := n1.StartDaemonAsIPNGOOS("windows")
	n1.AwaitResponding()
	n1.MustUp("--unattended")

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)
}
