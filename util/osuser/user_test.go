// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osuser

import (
	"context"
	"errors"
	"os/user"
	"reflect"
	"sync"
	"testing"
)

func TestProbeGetentDoubleDashSupport(t *testing.T) {
	origExecGetent := execGetent
	t.Cleanup(func() {
		execGetent = origExecGetent
	})

	tests := []struct {
		name string
		out  []byte
		err  error
		want bool
	}{
		{
			name: "supported",
			out:  []byte("root:x:0:0:root:/root:/bin/sh\n"),
			want: true,
		},
		{
			name: "error",
			err:  errors.New("unsupported"),
			want: false,
		},
		{
			name: "wrong-user",
			out:  []byte("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execGetent = func(_ context.Context, args ...string) ([]byte, error) {
				return tt.out, tt.err
			}
			if got := probeGetentDoubleDashSupport(); got != tt.want {
				t.Fatalf("probeGetentDashDashSupport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserLookupGetentUsesProbeResult(t *testing.T) {
	origExecGetent := execGetent
	origProbe := getentDoubleDashSupported
	t.Cleanup(func() {
		execGetent = origExecGetent
		getentDoubleDashSupported = origProbe
	})

	tests := []struct {
		name      string
		supported bool
		wantArgs  []string
	}{
		{
			name:      "supported",
			supported: true,
			wantArgs:  []string{"passwd", "--", "alice"},
		},
		{
			name:      "unsupported",
			supported: false,
			wantArgs:  []string{"passwd", "alice"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getentDoubleDashSupported = sync.OnceValue(func() bool { return tt.supported })
			execGetent = func(_ context.Context, args ...string) ([]byte, error) {
				if !reflect.DeepEqual(args, tt.wantArgs) {
					t.Fatalf("args = %q, want %q", args, tt.wantArgs)
				}
				return []byte("alice:x:1001:1001:Alice:/home/alice:/bin/sh\n"), nil
			}
			std := func(string) (*user.User, error) {
				t.Fatal("std lookup should not be called")
				return nil, nil
			}
			u, shell, err := userLookupGetent("alice", std)
			if err != nil {
				t.Fatalf("userLookupGetent error: %v", err)
			}
			if u.Username != "alice" || shell != "/bin/sh" {
				t.Fatalf("got user=%+v shell=%q", u, shell)
			}
		})
	}
}
