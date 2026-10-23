// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !js && !wasip1 && !wasm

package neterror

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestReadWasAborted(t *testing.T) {
	recvErr := func(errno error) error {
		// Shape that comes out of a real read: *net.OpError wrapping
		// an os.SyscallError, per the captures in #20616:
		//   *net.OpError, read udp4 0.0.0.0:41641: recvfrom: no route to host
		return &net.OpError{
			Op:  "read",
			Net: "udp4",
			Err: &os.SyscallError{
				Syscall: "recvfrom",
				Err:     errno,
			},
		}
	}

	tests := []struct {
		name string
		err  error
		// want is keyed by GOOS; "all" applies to every platform.
		want map[string]bool
	}{
		{"nil", nil, map[string]bool{"all": false}},
		{"non-syscall", errors.New("foo"), map[string]bool{"all": false}},
		{
			name: "host_unreach",
			err:  recvErr(syscall.EHOSTUNREACH),
			want: map[string]bool{"all": true},
		},
		{
			name: "host_down",
			err:  recvErr(syscall.EHOSTDOWN),
			want: map[string]bool{"darwin": true},
		},
		{
			name: "net_unreach",
			err:  recvErr(syscall.ENETUNREACH),
			want: map[string]bool{"darwin": true, "windows": true},
		},
		{
			name: "conn_reset",
			err:  recvErr(syscall.ECONNRESET),
			want: map[string]bool{"darwin": true, "windows": true},
		},
		{
			name: "net_reset",
			err:  recvErr(syscall.ENETRESET),
			want: map[string]bool{"darwin": true, "windows": true},
		},
		{
			name: "conn_refused",
			err:  recvErr(syscall.ECONNREFUSED),
			want: map[string]bool{"darwin": true},
		},
		// Errors that indicate the socket is unusable must never be
		// classified as an abort.
		{
			name: "closed_pipe",
			err:  &net.OpError{Op: "read", Err: os.ErrClosed},
			want: map[string]bool{"all": false},
		},
		{
			name: "epipe",
			err:  recvErr(syscall.EPIPE),
			want: map[string]bool{"all": false},
		},
		{
			name: "enotconn",
			err:  recvErr(syscall.ENOTCONN),
			want: map[string]bool{"all": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want bool
			if w, ok := tt.want["all"]; ok {
				want = w
			}
			if w, ok := tt.want[runtime.GOOS]; ok {
				want = w
			}
			if got := ReadWasAborted(tt.err); got != want {
				t.Errorf("ReadWasAborted() = %v, want %v (GOOS=%v)", got, want, runtime.GOOS)
			}
		})
	}
}
