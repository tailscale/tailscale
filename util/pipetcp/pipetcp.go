// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package pipetcp provides functionality to proxy connections between two TCP
// connections.
package pipetcp

import (
	"errors"
	"fmt"
	"io"
	"net"

	"tailscale.com/types/nettype"
)

// pump copies from src to dst until src returns EOF or either side fails.
//
// On EOF, it half-closes dst, if dst supports it, so dst's peer sees EOF while
// the other direction of the proxied connection keeps flowing.
// It does not half-close src's read side: that has no effect on the wire,
// and after src has returned EOF, both macOS and Linux may reject the shutdown
// with ENOTCONN.
//
// direction is a string used in the error text, used to denote the direction
// of a [pump]. This is because in a forwarding scenario, two [pump]s are
// started, to copy data from each direction to the other.
//
// Errors from writing to or half-closing dst are returned wrapped in a
// [dstError]. Errors from reading src are not.
func pump(dst, src net.Conn, direction string) error {
	if _, err := io.Copy(dstWriter{dst}, src); err != nil {
		return fmt.Errorf("%s: %w", direction, err)
	}
	// If the Copy finished without error, inform the other side that no more
	// data will be sent.
	if hc, ok := dst.(nettype.TCPWriteCloser); ok {
		if err := hc.CloseWrite(); err != nil {
			return fmt.Errorf("%s: close write: %w", direction, dstError{err})
		}
	}
	return nil
}

// Pipe bidirectionally connects `left` and `right`, two TCP streams (not
// necessarily [*net.TCPConn], but something that represents a TCP connection
// and is `CloseWrite()`-able), and closes the two connections when finished.
// It gracefully handles half-closed TCP connections on either side.
//
// When you call Pipe, you must ensure that both the Conns can be half-closed
// (ie. implement CloseWrite()). Otherwise, `Pipe` may block forever, or at
// least until both sides tear down their connections on their own.
func Pipe(left, right net.Conn) error {
	defer left.Close()
	defer right.Close()

	errc := make(chan error, 2)
	retErrs := make([]error, 2)
	go func() { errc <- pump(left, right, "right to left") }()
	go func() { errc <- pump(right, left, "left to right") }()

	closed := false
	for i := range 2 {
		err := <-errc

		// We ignore `net.ErrClosed` after we close the sockets, because we
		// know we did that.
		if !closed || !errors.Is(err, net.ErrClosed) {
			retErrs[i] = err
		}

		// One direction failed, which means one of the two sockets is dead.
		//
		// If it failed writing to (or half-closing) its destination, the other
		// direction is reading from that dead socket. Its reads return whatever
		// arrived before the failure and then an error, so leave it alone to
		// deliver that data rather than truncating it.
		//
		// If it failed reading from its source, the other direction is writing
		// into that dead socket and may be blocked reading from the live peer,
		// which has no reason to send anything. Close both connections to
		// unblock it. Nothing deliverable is lost: the dead socket has already
		// returned everything it received, and anything from the live peer
		// could not be delivered to it anyway.
		if err != nil && !isDstError(err) {
			left.Close()
			right.Close()
			closed = true
		}
	}
	return errors.Join(retErrs...)
}

// dstError wraps an error from [pump]'s destination, as opposed to one
// from reading its source.
type dstError struct{ error }

func (e dstError) Unwrap() error { return e.error }

// isDstError reports whether an error is from the destination of a [pump],
// rather than one from reading from its source.
func isDstError(err error) bool {
	_, ok := errors.AsType[dstError](err)
	return ok
}

// dstWriter wraps [pump]'s destination so that its write errors are
// reported as a [dstError].
//
// Wrapping the destination hides its ReadFrom method from [io.Copy] and hides
// its type from the source's WriteTo, so when both ends are bare TCP
// connections the kernel splice fast path is not used. That costs about a
// third of the relay throughput on Linux loopback, but knowing which side
// failed is what lets us avoid truncating a reply after the backend
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
