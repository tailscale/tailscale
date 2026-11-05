// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsClosedPipeError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{windows.ERROR_NO_DATA, true},
		{syscall.EPIPE, true},
		{syscall.ENOTCONN, true},
		{fs.ErrClosed, true},
		{io.ErrClosedPipe, true},
		{windows.WSAECONNRESET, false},
	} {
		if got := IsClosedPipeError(tt.err); got != tt.want {
			t.Errorf("IsClosedPipeError(%v) = %v, want %v", tt.err, got, tt.want)
		}
		if got := IsClosedPipeError(fmt.Errorf("wrapped: %w", tt.err)); got != tt.want {
			t.Errorf("IsClosedPipeError(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestIsBadSocketError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{windows.WSAEBADF, true},
		{windows.WSAENOTSOCK, true},
		{windows.WSAECONNRESET, false},
		{syscall.EBADF, false},
		{syscall.ENOTSOCK, false},
		{net.ErrClosed, false},
	} {
		if got := IsBadSocketError(tt.err); got != tt.want {
			t.Errorf("IsBadSocketError(%v) = %v, want %v", tt.err, got, tt.want)
		}
		wrapped := &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{
			Syscall: "WSARecvFrom", Err: tt.err,
		}}
		if got := IsBadSocketError(wrapped); got != tt.want {
			t.Errorf("IsBadSocketError(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
