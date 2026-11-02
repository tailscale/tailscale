// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package neterror

import (
	"errors"
	"io"
	"io/fs"
	"syscall"
)

// IsUDPReadFeedback reports whether err is host or network reachability
// feedback reported by a UDP read, rather than a socket failure.
func IsUDPReadFeedback(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	// EPIPE/ENOTCONN are common errors when a send fails due to a closed
	// socket. There is some platform and version inconsistency in which
	// error is returned, but the meaning is the same.
	// Libraries may also return root errors like fs.ErrClosed/io.ErrClosedPipe
	// due to a closed socket.
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENOTCONN) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}
