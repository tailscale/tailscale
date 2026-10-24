// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredUID returns the effective uid of the peer of a connected unix
// socket, read from the listening side with SO_PEERCRED.
func peerCredUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix conn")
	}
	f, err := uc.File()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	u, err := unix.GetsockoptUcred(int(f.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(u.Uid), nil
}
