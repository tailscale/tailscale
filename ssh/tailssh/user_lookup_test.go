// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestUserLookupNumericFallback(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	want, err := user.LookupId(uid)
	if err != nil {
		t.Fatal(err)
	}
	// Force the no-getent path: numeric policy mappings must fall back to
	// os/user.LookupId, not try to find a username consisting of the UID.
	t.Setenv("PATH", t.TempDir())
	got, err := userLookup(uid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != want.Username || got.Uid != want.Uid || got.Gid != want.Gid {
		t.Fatalf("userLookup(%q) = %+v; want %+v", uid, got, want)
	}
}
