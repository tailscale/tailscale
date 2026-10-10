// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package msgx sends and receives multiple datagrams per system call on macOS
// using the kernel's recvmsg_x and sendmsg_x entry points, the Darwin
// counterparts of Linux's recvmmsg and sendmmsg.
//
// [Available] reports whether this package may be used. The system calls need
// no special privileges, but because Apple considers them a private/unstable
// API, they're not used in processes subject to App Store review, and they're
// self-tested at runtime before use. That self-test's outcome is exported as
// client metrics so we can detect whether the API is still working.
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
