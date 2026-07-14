// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package integration

// Non-Windows stubs for the Windows service backend; never called, since
// windowsService is only set on Windows.

func (n *TestNode) startWindowsServiceDaemon() *Daemon {
	n.env.t.Fatal("Windows service daemon is only supported on Windows")
	return nil
}

func (n *TestNode) stopService() {
	n.env.t.Fatal("Windows service daemon is only supported on Windows")
}
