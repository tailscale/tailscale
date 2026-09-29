// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package msgx sends and receives multiple datagrams per system call on
// macOS using the kernel's recvmsg_x and sendmsg_x entry points, the Darwin
// counterparts of Linux's recvmmsg and sendmmsg.
//
// Those entry points are declared only in xnu's private socket_private.h and
// are not part of any public API, so this package makes them as raw system
// calls by number rather than through libSystem. That keeps their names out
// of the binary, gives a reliable errno (the trap's carry flag, rather than a
// separate __error() read that can race with other libc calls on the same
// thread), and avoids a cgo transition per call.
//
// [Available] reports whether this package may be used. The system calls
// need no special privileges, but their use is deliberately limited: never
// from a sandboxed App Store process (Apple's review process forbids
// non-public APIs there), whether Tailscale's own GUI builds or a third-party
// app embedding tsnet; and only after a loopback self-test exchanging real
// datagrams with the running kernel passes, since Apple does not promise that
// system call numbers or private structure layouts stay stable across
// releases. When Available reports false, every other function returns
// [ErrUnavailable] and callers must fall back to one datagram per call.
//
// The self-test's outcome is exported as client metrics (msgx_selftest_ran,
// msgx_selftest_passed, msgx_selftest_failure) so that a kernel change in
// the wild shows up rather than silently disabling batching.
//
// Both entry points work on any socket type the kernel treats as a datagram
// socket, including the utun kernel control socket, not only UDP.
package msgx

import (
	"errors"
	"net/netip"
)

// ErrUnavailable is returned by [Recv] and [Send] when [Available] is false.
var ErrUnavailable = errors.New("msgx: recvmsg_x/sendmsg_x unavailable")

// MaxBatch is the most messages [Recv] or [Send] handle per call. Callers may
// pass more; the excess is ignored by Recv and left for a later call by Send.
// The kernel itself clamps a call to 256 messages (its somaxrecvmsgx and
// somaxsendmsgx sysctls); 128 matches wireguard-go's ideal batch size.
const MaxBatch = 128

// Message is one received datagram.
type Message struct {
	// Payload is the caller-provided buffer to receive into. A datagram
	// larger than Payload is truncated; see Flags.
	Payload []byte

	// N is the number of bytes written into Payload.
	N int

	// Addr is the datagram's source address, if the socket reports one.
	Addr netip.AddrPort

	// Flags holds the kernel's per-message flags. The header documents
	// syscall.MSG_TRUNC for a truncated datagram, but macOS 26 and later
	// have been observed to clamp N to len(Payload) without setting it,
	// so callers should size Payload above the largest datagram they
	// expect rather than rely on this.
	Flags int
}
