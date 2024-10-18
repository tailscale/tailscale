// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package ipnauth

import (
	"net"

	"github.com/tailscale/peercred"
	"tailscale.com/types/logger"
)

// GetConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
// and couldn't. The returned connIdentity has NotWindows set to true.
func GetConnIdentity(_ logger.Logf, c net.Conn) (ci *ConnIdentity, err error) {
	ci = &ConnIdentity{conn: c, notWindows: true}
	_, ci.isUnixSock = c.(*net.UnixConn)
	if ci.creds, _ = peercred.Get(c); ci.creds != nil {
		ci.pid, _ = ci.creds.PID()
	}
	return ci, nil
}

// WindowsToken is unsupported when GOOS != windows and always returns
// ErrNotImplemented.
func (ci *ConnIdentity) WindowsToken() (WindowsToken, error) {
	return nil, ErrNotImplemented
}
