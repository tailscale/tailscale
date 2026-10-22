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

func TestIsUDPReadFeedback(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{syscall.EHOSTUNREACH, true},
		{syscall.ENETUNREACH, true},
		{syscall.EHOSTDOWN, false},
		{syscall.ENETRESET, false},
		{syscall.ECONNRESET, false},
		{syscall.ECONNREFUSED, false},
		{syscall.EBADF, false},
		{syscall.ENOTSOCK, false},
		{syscall.EPIPE, false},
		{syscall.ENOTCONN, false},
		{net.ErrClosed, false},
	}
	for _, tt := range tests {
		if got := IsUDPReadFeedback(tt.err); got != tt.want {
			t.Errorf("IsUDPReadFeedback(%v) = %v, want %v", tt.err, got, tt.want)
		}
		wrapped := &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{
			Syscall: "recvfrom", Err: tt.err,
		}}
		if got := IsUDPReadFeedback(wrapped); got != tt.want {
			t.Errorf("IsUDPReadFeedback(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
