// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package tailssh

import "golang.org/x/sys/unix"

// pidGone reports whether pid is absent or a zombie.
func pidGone(pid int) bool {
	const szomb = 5 // SZOMB in <sys/proc.h>.
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		return unix.Kill(pid, 0) == unix.ESRCH
	}
	return len(procs) == 0 || procs[0].Proc.P_stat == szomb
}
