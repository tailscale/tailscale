// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !js && !wasip1 && !wasm

package neterror

import (
	"errors"
	"io"
	"io/fs"
	"runtime"
	"syscall"
)

// ReadWasAborted reports whether err is a datagram receive error meaning
// the kernel aborted a blocked read without delivering a packet, while the
// socket itself remains usable: callers should keep reading rather than
// tearing the socket down.
//
// macOS delivers EHOSTUNREACH to wildcard sockets on interface/route churn
// (captured in the wild hitting magicsock's receive funcs, #20616) and
// ICMP-derived feedback to unconnected reads; Windows surfaces
// WSAECONNRESET on an unconnected receive after a prior send provoked an
// ICMP error.
//
// The set is deliberately narrow: nothing indicating the socket is closed
// or broken is included. The same errnos on *send* paths do carry
// peer-reachability information (see magicsock's isBadEndpointErr); this
// predicate is only about reads.
func ReadWasAborted(err error) bool {
	if err == nil {
		return false
	}
	switch runtime.GOOS {
	case "darwin", "ios":
		// Route/interface churn and ICMP feedback on unconnected reads
		// (in_pcbnotify and friends); EHOSTUNREACH captured in #20616.
		return errors.Is(err, syscall.EHOSTUNREACH) ||
			errors.Is(err, syscall.EHOSTDOWN) ||
			errors.Is(err, syscall.ENETUNREACH) ||
			errors.Is(err, syscall.ENETRESET) ||
			errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET)
	case "windows":
		// Go does not disable SIO_UDP_CONNRESET (unlike WSAENETRESET,
		// which magicsock disables per-socket via
		// sockopts.SetICMPErrImmunity, see golang/go#5834), so
		// WSAECONNRESET is expected on reads. Go maps WSA socket errors
		// to unix errno names: ECONNRESET=WSAECONNRESET,
		// ENETRESET=WSAENETRESET, EHOSTUNREACH=WSAEHOSTUNREACH.
		return errors.Is(err, syscall.EHOSTUNREACH) ||
			errors.Is(err, syscall.ENETUNREACH) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ENETRESET)
	default:
		// Linux and the BSDs do not surface route or ICMP errors on reads
		// from unconnected sockets; tolerating strays is harmless and
		// beats a receive goroutine that dies for good.
		return errors.Is(err, syscall.EHOSTUNREACH)
	}
}

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	// 232 is Windows error code ERROR_NO_DATA, "The pipe is being closed".
	if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(232)) {
		return true
	}

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
