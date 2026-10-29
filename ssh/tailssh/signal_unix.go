// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"os"
	"syscall"
)

// signalProcessGroup sends sig to p's whole process group when p is the
// group's leader (addressing the group by -pid), else to p alone. Signaling
// the group reaches the descendants that share it; see
// sshSession.signalSessionProcess.
func signalProcessGroup(p *os.Process, sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		if pgid, err := syscall.Getpgid(p.Pid); err == nil && pgid == p.Pid {
			syscall.Kill(-p.Pid, s)
			return
		}
	}
	p.Signal(sig)
}
