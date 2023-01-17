// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package neterror classifies network errors.
package neterror

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
)

var errEPERM error = syscall.EPERM // box it into interface just once

// TreatAsLostUDP reports whether err is an error from a UDP send
// operation that should be treated as a UDP packet that just got
// lost.
//
// Notably, on Linux this reports true for EPERM errors (from outbound
// firewall blocks) which aren't really send errors; they're just
// sends that are never going to make it because the local OS blocked
// it.
func TreatAsLostUDP(err error) bool {
	if err == nil {
		return false
	}
	switch runtime.GOOS {
	case "linux":
		// Linux, while not documented in the man page,
		// returns EPERM when there's an OUTPUT rule with -j
		// DROP or -j REJECT.  We use this very specific
		// Linux+EPERM check rather than something super broad
		// like net.Error.Temporary which could be anything.
		//
		// For now we only do this on Linux, as such outgoing
		// firewall violations mapping to syscall errors
		// hasn't yet been observed on other OSes.
		return errors.Is(err, errEPERM)
	}
	return false
}

var packetWasTruncated func(error) bool // non-nil on Windows at least

// PacketWasTruncated reports whether err indicates truncation but the RecvFrom
// that generated err was otherwise successful. On Windows, Go's UDP RecvFrom
// calls WSARecvFrom which returns the WSAEMSGSIZE error code when the received
// datagram is larger than the provided buffer. When that happens, both a valid
// size and an error are returned (as per the partial fix for golang/go#14074).
// If the WSAEMSGSIZE error is returned, then we ignore the error to get
// semantics similar to the POSIX operating systems. One caveat is that it
// appears that the source address is not returned when WSAEMSGSIZE occurs, but
// we do not currently look at the source address.
func PacketWasTruncated(err error) bool {
	if packetWasTruncated == nil {
		return false
	}
	return packetWasTruncated(err)
}

var shouldDisableUDPGSO func(error) bool // non-nil on Linux

func ShouldDisableUDPGSO(err error) bool {
	if shouldDisableUDPGSO == nil {
		return false
	}
	return shouldDisableUDPGSO(err)
}

type ErrUDPGSODisabled struct {
	OnLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.OnLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}
