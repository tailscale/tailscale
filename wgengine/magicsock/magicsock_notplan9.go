// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package magicsock

import (
	"errors"
	"runtime"
	"syscall"

	"tailscale.com/net/neterror"
)

// shouldRebind returns if the error is one that is known to be healed by a
// rebind, and if so also returns a resason string for the rebind.
func shouldRebind(err error) (ok bool, reason string) {
	switch {
	// EPIPE/ENOTCONN are common errors when a send fails due to a closed
	// socket. There is some platform and version inconsistency in which
	// error is returned, but the meaning is the same.
	case neterror.IsClosedPipeError(err):
		return true, "broken-pipe"

	// EPERM is typically caused by EDR software, and has been observed to be
	// transient, it seems that some versions of some EDR lose track of sockets
	// at times, and return EPERM, but reconnects will establish appropriate
	// rights associated with a new socket.
	case errors.Is(err, syscall.EPERM):
		return true, "operation-not-permitted"
	}
	return false, ""
}

// shouldRebindRead reports whether err from a read is known to be healed by a
// rebind.
//
// Some of these errors are known to be used by EDR software to shut down conns.
func shouldRebindRead(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EBADF, syscall.ENOTSOCK:
		return true
	}
	// WSAEBADF and WSAENOTSOCK. On Windows the constants above are
	// APPLICATION_ERROR pseudo-errnos, which a read never returns.
	return runtime.GOOS == "windows" && (errno == 10009 || errno == 10038)
}
