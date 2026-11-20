// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package pumptcp provides functionality to pipe one TCP connection to another,
// for use in TCP forwarding proxies.
package pumptcp

import (
	"errors"
	"fmt"
	"io"
	"net"

	"tailscale.com/types/nettype"
)

// Copy copies from src to dst until src returns EOF or either side fails.
//
// On EOF it half-closes dst, if dst supports it, so dst's peer sees EOF while
// the other direction of the proxied connection keeps flowing. It does not
// half-close src's read side: that has no effect on the wire, and after src
// has returned EOF, both macOS and Linux may reject the shutdown with
// ENOTCONN.
//
// direction is a string used in the error text, used to denote the direction
// of a [Copy]. This is because in a forwarding scenario, two [Copy]s are
// started, to copy data from each direction to the other.
//
// Errors from writing to or half-closing dst are returned wrapped in a
// [dstError]. Errors from reading src are not.
//
// When you call Copy, you must ensure that the destination Conn can be
// half-closed (ie. implements CloseWrite()).
func Copy(dst, src net.Conn, direction string) error {
	if _, err := io.Copy(dstWriter{dst}, src); err != nil {
		return fmt.Errorf("%s: %w", direction, err)
	}
	if hc, ok := dst.(nettype.TCPWriteCloser); ok {
		if err := hc.CloseWrite(); err != nil {
			return fmt.Errorf("%s: close write: %w", direction, dstError{err})
		}
	}
	return nil
}

// dstError wraps an error from [Copy]'s destination, as opposed to one
// from reading its source.
type dstError struct{ error }

func (e dstError) Unwrap() error { return e.error }

// IsDstError reports whether an error is from the destination of a [Copy],
// rather than one from reading from its source.
func IsDstError(err error) bool {
	_, ok := errors.AsType[dstError](err)
	return ok
}

// dstWriter wraps [Copy]'s destination so that its write errors are
// reported as a [dstError].
//
// Wrapping the destination hides its ReadFrom method from [io.Copy] and hides
// its type from the source's WriteTo, so when both ends are bare TCP
// connections the kernel splice fast path is not used. That costs about a
// third of the relay throughput on Linux loopback, but knowing which side
// failed is what lets handleTCP avoid truncating a reply after the backend
// resets, and in the common userspace-networking and proxymux configurations
// the connections are wrapped types with no fast path anyway.
type dstWriter struct{ io.Writer }

func (w dstWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err != nil {
		err = dstError{err}
	}
	return n, err
}
