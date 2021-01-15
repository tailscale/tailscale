// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package ipnserver

import (
	"net"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

func isReadonlyConn(c net.Conn, logf logger.Logf) (ro bool) {
	ro = true // conservative default for naked returns below
	uc, ok := c.(*net.UnixConn)
	if !ok {
		logf("unexpected connection type %T", c)
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		logf("SyscallConn: %v", err)
		return
	}

	var cred *unix.Ucred
	cerr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED)
	})
	if cerr != nil {
		logf("raw.Control: %v", err)
		return
	}
	if err != nil {
		logf("raw.Control: %v", err)
		return
	}
	if cred.Uid == 0 {
		// root is not read-only.
		return false
	}
	logf("non-root connection from %v (read-only)", cred.Uid)
	return true
}
