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

func TestIsUDPReadFeedback(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{windows.WSAEHOSTUNREACH, true},
		{windows.WSAENETUNREACH, true},
		{windows.WSAEHOSTDOWN, false},
		{windows.WSAENETRESET, false},
		{windows.WSAECONNRESET, false},
		{windows.WSAECONNREFUSED, false},
		{windows.WSAEBADF, false},
		{windows.WSAENOTSOCK, false},
		{windows.WSAENOTCONN, false},
		{syscall.EHOSTUNREACH, false},
		{syscall.ENETUNREACH, false},
		{net.ErrClosed, false},
	} {
		if got := IsUDPReadFeedback(tt.err); got != tt.want {
			t.Errorf("IsUDPReadFeedback(%v) = %v, want %v", tt.err, got, tt.want)
		}
		wrapped := &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{
			Syscall: "WSARecvFrom", Err: tt.err,
		}}
		if got := IsUDPReadFeedback(wrapped); got != tt.want {
			t.Errorf("IsUDPReadFeedback(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

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
