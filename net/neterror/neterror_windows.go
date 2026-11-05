// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"io"
	"io/fs"
	"syscall"

	"golang.org/x/sys/windows"
)

// IsBadSocketError reports whether err indicates that the socket itself is no
// longer valid.
func IsBadSocketError(err error) bool {
	return errors.Is(err, windows.WSAEBADF) || errors.Is(err, windows.WSAENOTSOCK)
}

// IsClosedPipeError reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	return errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENOTCONN) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}

func init() {
	packetWasTruncated = func(err error) bool {
		return errors.Is(err, windows.WSAEMSGSIZE)
	}
}
