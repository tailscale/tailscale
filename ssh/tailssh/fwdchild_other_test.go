// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"errors"
	"net"
)

// peerCredUID is not implemented on this platform; it always returns an
// error.
func peerCredUID(c net.Conn) (int, error) {
	return 0, errors.New("peer cred not implemented on this platform")
}
