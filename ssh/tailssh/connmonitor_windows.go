// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

// connMonitorState is the Windows stand-in for the Unix process monitor's
// per-connection state. Windows has no monitor: sessions run under the
// target user's token directly (see process_windows.go), so there is
// nothing to track and nothing to close.
type connMonitorState struct{}

func (connMonitorState) close() {}

func (c *conn) closeConnMonitor() { c.monitor.close() }
