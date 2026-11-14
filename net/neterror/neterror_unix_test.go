// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package neterror

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsBadSocketError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{syscall.EBADF, true},
		{syscall.ENOTSOCK, true},
		{syscall.EPIPE, false},
		{syscall.EHOSTUNREACH, false},
		{net.ErrClosed, false},
	} {
		if got := IsBadSocketError(tt.err); got != tt.want {
			t.Errorf("IsBadSocketError(%v) = %v, want %v", tt.err, got, tt.want)
		}
		wrapped := &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{
			Syscall: "recvfrom", Err: tt.err,
		}}
		if got := IsBadSocketError(wrapped); got != tt.want {
			t.Errorf("IsBadSocketError(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
