// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (darwin && !ios) || freebsd || openbsd

package tailssh

import "syscall"

// monChildAttr returns the SysProcAttr for one monitor child. This
// variant carries no Pdeathsig because that field does not exist on
// these platforms.
func monChildAttr(ctty bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: !ctty,
		Setsid:  ctty,
		Setctty: ctty,
	}
}

// scrubFds marks every open descriptor from 3 up close-on-exec, so the
// monitor cannot leak an inherited or late-created descriptor into a
// child it execs. There is no close_range on these platforms; scan the
// self-fd directory instead.
func scrubFds() error {
	if err := scrubFdsByScan("/dev/fd"); err == nil {
		return nil
	}
	return scrubFdsByScan("/proc/self/fd")
}
