// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

// monChildAttr returns the SysProcAttr for one monitor child. A ctty
// child gets Setsid+Setctty with the pty slave as its fd 0; Setpgid is
// set only for non-ctty children. Pdeathsig is advisory: it fires on
// the exit of the creating thread, not the process, per golang/go#27505.
func monChildAttr(ctty bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   !ctty,
		Setsid:    ctty,
		Setctty:   ctty,
		Pdeathsig: unix.SIGHUP,
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

// fwdChildAttr returns the SysProcAttr for a one-shot forwarding child
// whose identity must be applied, that is a root monitor's child. The
// Credential carries the connection's bound identity from ma. The child
// leads its own group so the op deadline and teardown can kill the
// whole group, and Pdeathsig is set as in monChildAttr.
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
