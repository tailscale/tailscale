// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin || ios

package msgx

import (
	"errors"
	"syscall"
)

var errNotDarwin = errors.New("msgx: only supported on macOS")

// Available reports whether recvmsg_x and sendmsg_x may be used by this
// process. It is always false here.
func Available() bool { return false }

// UnavailableReason returns why [Available] is false.
func UnavailableReason() error { return errNotDarwin }

// Recv implements the package API; it always returns [ErrUnavailable].
func Recv(rc syscall.RawConn, msgs []Message) (int, error) {
	return 0, ErrUnavailable
}

// Send implements the package API; it always returns [ErrUnavailable].
func Send(rc syscall.RawConn, payloads [][]byte) (int, error) {
	return 0, ErrUnavailable
}
