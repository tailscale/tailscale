// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

// monChildAttr returns process attributes for a session child.
// With ctty, the child starts a session with fd 0 as its controlling terminal.
// Otherwise it starts a process group.
// Pdeathsig is unset so the child can survive monitor exit.
func monChildAttr(ctty bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: !ctty,
		Setsid:  ctty,
		Setctty: ctty,
	}
}

// scrubFds marks every open descriptor from 3 up close-on-exec, so the
// monitor cannot leak an inherited or late-created descriptor into a
// child it execs. close_range(CLOSE_RANGE_CLOEXEC) does this in one
// atomic syscall on kernels 5.11 and later; older kernels fall back to
// a /proc/self/fd enumeration.
func scrubFds() error {
	if err := unix.CloseRange(3, math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return nil
	}
	return scrubFdsByScan("/proc/self/fd")
}

// fwdChildAttr returns process attributes for a forwarding child.
// The child runs with ma's credentials in its own process group.
// Pdeathsig sends SIGHUP when the creating thread exits. See golang/go#27505.
func fwdChildAttr(ma monitorArgs) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    ma.uid,
			Gid:    ma.gid,
			Groups: fwdCredGroups(ma.gid, ma.gids),
		},
		Setpgid:   true,
		Pdeathsig: unix.SIGHUP,
	}
}
