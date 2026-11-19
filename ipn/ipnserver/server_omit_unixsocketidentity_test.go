// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && ts_omit_unixsocketidentity

package ipnserver

import (
	"testing"

	"tailscale.com/ipn/ipnauth"
)

func TestActorPermissionsWithoutUnixSocketIdentity(t *testing.T) {
	a := &actor{
		ci: &ipnauth.ConnIdentity{},
	}

	read, write := a.Permissions("")
	if !read || !write {
		t.Fatalf("Permissions() = (%v, %v), want (true, true)", read, write)
	}
}
