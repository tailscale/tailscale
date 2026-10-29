// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package tailssh

import (
	"os"
)

// signalProcessGroup sends sig to p. Plan 9 has no process groups, so the
// signal reaches only the session process itself; descendants are handled
// by the bounded I/O drain in sshSession.run.
func signalProcessGroup(p *os.Process, sig os.Signal) {
	p.Signal(sig)
}
