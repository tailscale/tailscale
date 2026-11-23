// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"os/user"
	"testing"
)

func TestIsCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("can't determine current user: %v", err)
	}
	if !isCurrentUser(u.Username) {
		t.Errorf("isCurrentUser(%q) = false; want true", u.Username)
	}
	for _, name := range []string{"", u.Username + "-not-me"} {
		if isCurrentUser(name) {
			t.Errorf("isCurrentUser(%q) = true; want false", name)
		}
	}
}
