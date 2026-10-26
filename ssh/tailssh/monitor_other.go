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

// fwdChildAttr returns the SysProcAttr for a one-shot forwarding child
// whose identity must be applied, that is a root monitor's child. The
// Credential carries the connection's bound identity from ma, and the
// child leads its own group. This variant has no Pdeathsig field; see
// monitor_linux.go.
func fwdChildAttr(ma monitorArgs) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    ma.uid,
			Gid:    ma.gid,
			Groups: fwdCredGroups(ma.gid, ma.gids),
		},
		Setpgid: true,
	}
}
