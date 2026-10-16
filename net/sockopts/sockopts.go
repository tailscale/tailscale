// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package sockopts contains logic for applying socket options.
package sockopts

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"tailscale.com/types/nettype"
)

// RawConn returns the socket underlying pconn.
//
// The error wraps [ErrNoSocket] if pconn has no socket.
func RawConn(pconn nettype.PacketConn) (syscall.RawConn, error) {
	sc, ok := pconn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("%T: %w", pconn, ErrNoSocket)
	}
	return sc.SyscallConn()
}

// ErrNoSocket reports that there is no socket to apply an option to,
// distinct from the kernel refusing the option on one.
var ErrNoSocket = errors.New("no socket to configure")

// ControlEach runs the system call fn on the socket of every conn in pconns.
// It reports [ErrNoSocket] without calling fn if pconns is empty or if any
// conn has no socket; otherwise it calls fn for each socket before returning,
// and returns the join of fn's errors.
func ControlEach(pconns []nettype.PacketConn, fn func(fd uintptr) error) error {
	if len(pconns) == 0 {
		return fmt.Errorf("empty group: %w", ErrNoSocket)
	}
	rcs := make([]syscall.RawConn, len(pconns))
	for i, pconn := range pconns {
		rc, err := RawConn(pconn)
		if err != nil {
			return fmt.Errorf("socket %d of %d: %w", i, len(pconns), err)
		}
		rcs[i] = rc
	}
	var errs []error
	for _, rc := range rcs {
		if err := rc.Control(func(fd uintptr) {
			if err := fn(fd); err != nil {
				errs = append(errs, err)
			}
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ControlFunc is the Control hook of a [net.ListenConfig].
type ControlFunc func(network, address string, c syscall.RawConn) error

// BufferDirection represents either the read/receive or write/send direction
// of a socket buffer.
type BufferDirection string

const (
	ReadDirection  BufferDirection = "read"
	WriteDirection BufferDirection = "write"
)

func portableSetBufferSize(pconn nettype.PacketConn, direction BufferDirection, size int) error {
	if runtime.GOOS == "plan9" {
		// Not supported. Don't try. Avoid logspam.
		return nil
	}
	var err error
	if c, ok := pconn.(*net.UDPConn); ok {
		if direction == WriteDirection {
			err = c.SetWriteBuffer(size)
		} else {
			err = c.SetReadBuffer(size)
		}
	}
	return err
}
