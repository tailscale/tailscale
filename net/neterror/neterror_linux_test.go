// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestTreatAsLostUDP(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"non-nil", errors.New("foo"), false},
		{"eperm", syscall.EPERM, true},
		{
			name: "operror",
			err: &net.OpError{
				Op: "write",
				Err: &os.SyscallError{
					Syscall: "sendto",
					Err:     syscall.EPERM,
				},
			},
			want: true,
		},
		{
			name: "host_unreach",
			err: &net.OpError{
				Op: "write",
				Err: &os.SyscallError{
					Syscall: "sendto",
					Err:     syscall.EHOSTUNREACH,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TreatAsLostUDP(tt.err); got != tt.want {
				t.Errorf("got = %v; want %v", got, tt.want)
			}
		})
	}

}
