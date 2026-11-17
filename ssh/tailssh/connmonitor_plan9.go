// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package tailssh

// connMonitorState is empty because Plan 9 does not use a process monitor.
type connMonitorState struct{}

func (c *conn) closeConnMonitor() {}
