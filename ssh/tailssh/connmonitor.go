// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// connMonitorState owns the connection's process monitor. It is started
// on the first session or forwarding request and closed at connection teardown.
// Its local user, UID, GID, and supplementary groups are fixed at startup
// from the identity selected by clientAuth.
type connMonitorState struct {
	mu  sync.Mutex
	mon *monitorClient

	// closed is set by closeConnMonitor, before the lock is dropped. Once
	// the conn's teardown has run, connMonitor refuses to spawn.
	// connMonitorIfAny is unaffected.
	closed bool

	// exits routes notifications by child handle. Its callback is installed
	// at monitor spawn.
	exits monExitRegistry
}

// connMonitor returns the conn's monitor, spawning it on first use with
// the spawn-bound identity documented on connMonitorState.
func (c *conn) connMonitor() (*monitorClient, error) {
	c.monitor.mu.Lock()
	defer c.monitor.mu.Unlock()
	if c.monitor.mon != nil {
		return c.monitor.mon, nil
	}
	if c.monitor.closed {
		return nil, errors.New("monitor closed at connection teardown")
	}
	uid, gid, groups, err := c.monitorCreds()
	if err != nil {
		return nil, err
	}
	// The monitor is exec'd from the tailscaled binary; in tests
	// os.Executable() is the test binary. The incubator spawn takes the
	// same path from srv.tailscaledPath.
	exe := c.srv.tailscaledPath
	if exe == "" {
		exe, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("ssh-monitor: executable: %w", err)
		}
	}
	mc, err := spawnMonitor(exe, uid, gid, groups, c.localUser.Username)
	if err != nil {
		return nil, fmt.Errorf("spawning ssh-monitor for %q: %w", c.localUser.Username, err)
	}
	// Route the monitor's async exit notifications to the conn's
	// sessions in sessmonitor.go.
	mc.SetExitCallback(c.monitor.exits.dispatchExit)
	c.monitor.mon = mc
	return mc, nil
}

// connMonitorIfAny returns the connection's monitor without starting one.
// It returns nil before startup and after closeConnMonitor.
func (c *conn) connMonitorIfAny() *monitorClient {
	c.monitor.mu.Lock()
	defer c.monitor.mu.Unlock()
	return c.monitor.mon
}

// monitorCreds returns the monitor's spawn identity, parsing like the
// incubator's argv does. The ids are carried at their 32-bit ABI width.
func (c *conn) monitorCreds() (uid, gid uint32, groups []uint32, err error) {
	u64, err := strconv.ParseUint(c.localUser.Uid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("ssh-monitor: parsing local user uid %q: %w", c.localUser.Uid, err)
	}
	g64, err := strconv.ParseUint(c.localUser.Gid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("ssh-monitor: parsing local user gid %q: %w", c.localUser.Gid, err)
	}
	for _, g := range c.userGroupIDs {
		v, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("ssh-monitor: parsing local user group %q: %w", g, err)
		}
		groups = append(groups, uint32(v))
	}
	return uint32(u64), uint32(g64), groups, nil
}

// closeConnMonitor closes the conn's monitor, if one was spawned. It
// runs from HandleSSHConn's defer after the SSH connection is done.
// Closing the RPC channel triggers the monitor's teardown in monitor.go.
// Closing a second time is a no-op.
func (c *conn) closeConnMonitor() {
	c.monitor.mu.Lock()
	mc := c.monitor.mon
	c.monitor.mon = nil
	c.monitor.closed = true
	c.monitor.mu.Unlock()
	if mc == nil {
		return
	}
	if err := mc.Close(); err != nil {
		c.logf("ssh: closing connection monitor: %v", err)
	}
}
