// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd || openbsd

package osuser

import (
	"context"
	"errors"
	"os/exec"
	"os/user"
	"testing"

	"tailscale.com/tstest"
)

func TestUserLookupGetentFallbackErrors(t *testing.T) {
	exitError := func(code string, want int) error {
		err := exec.Command("sh", "-c", "exit "+code).Run()
		if e, ok := errors.AsType[*exec.ExitError](err); !ok || e.ExitCode() != want {
			t.Fatalf("getting exit %d: %v", want, err)
		}
		return err
	}
	exit1, exit2 := exitError("1", 1), exitError("2", 2)
	for _, tt := range []struct {
		name        string
		output      string
		getentErr   error
		fallbackErr error
		wantMissing bool
		wantErr     bool
	}{
		{name: "command-failure-directory-user", getentErr: exit1, fallbackErr: user.UnknownUserError("alice"), wantErr: true},
		{name: "timeout-directory-user", getentErr: context.DeadlineExceeded, fallbackErr: user.UnknownUserError("alice"), wantErr: true},
		{name: "corrupt-output-directory-user", output: "broken passwd record", fallbackErr: user.UnknownUserError("alice"), wantErr: true},
		{name: "outage-local-user", getentErr: errors.New("NSS unavailable")},
		{name: "not-found", getentErr: exit2, fallbackErr: user.UnknownUserError("alice"), wantMissing: true, wantErr: true},
		{name: "getent-not-installed", getentErr: exec.ErrNotFound, fallbackErr: user.UnknownUserError("alice"), wantMissing: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tstest.Replace(t, &execGetent, func(context.Context, ...string) ([]byte, error) {
				return []byte(tt.output), tt.getentErr
			})
			tstest.Replace(t, &getentDoubleDashSupported, func() bool { return false })
			u, _, err := userLookupGetent("alice", func(name string) (*user.User, error) {
				if name != "alice" {
					t.Fatalf("fallback name = %q", name)
				}
				if tt.fallbackErr != nil {
					return nil, tt.fallbackErr
				}
				return &user.User{Username: "alice", Uid: "1001", Gid: "1001"}, nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			_, missing := errors.AsType[user.UnknownUserError](err)
			if missing != tt.wantMissing {
				t.Errorf("error = %v; missing = %v, want %v", err, missing, tt.wantMissing)
			}
			if !tt.wantErr && (u == nil || u.Username != "alice") {
				t.Errorf("fallback user = %v", u)
			}
		})
	}
}
