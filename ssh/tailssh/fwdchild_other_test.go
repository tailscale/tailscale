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

// dumpChildFdsTo is a no-op off linux. The exec-inheritance fd dump
// reads /proc, and every test gating on it skips on these platforms
// anyway.
func dumpChildFdsTo(path, tag string) {}
