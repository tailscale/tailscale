// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,!redo

package ipnserver

import (
	"net"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

const (
	xLOCAL_PEERCRED  = 0x1
	xLOCAL_PEEREPID  = 0x3
	xLOCAL_PEEREUUID = 0x5
	xLOCAL_PEERPID   = 0x2
	xLOCAL_PEERUUID  = 0x4
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

	var cred unix.Xucred
	cerr := raw.Control(func(fd uintptr) {
		err = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED, &cred)
	})
	if cerr != nil {
		logf("raw.Control: %v", err)
		return
	}
	if err != nil {
		logf("raw.GetsockoptXucred: %v", err)
		return
	}
	logf("XXX got creds %+v", cred)
	if cred.Uid == 0 {
		// root is not read-only.
		return false
	}
	logf("non-root connection from %v (read-only)", cred.Uid)
	return true
}
