// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package neterror classifies network errors.
package neterror

import (
	"errors"
	"fmt"
	"syscall"
)

var errEPERM error = syscall.EPERM // box it into interface just once

// IsEPERM returns true if the error is or wraps EPERM.
func IsEPERM(err error) bool {
	// Linux and macOS, while not documented in the man page, returns EPERM when
	// there's a rule rejecting matching sendto(2) destinations.
	//
	// We use this very specific Linux+EPERM check rather than something super
	// broad like net.Error.Temporary which could be anything.
	return errors.Is(err, errEPERM)
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
