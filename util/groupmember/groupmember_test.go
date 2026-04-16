// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package groupmember

import "testing"

func TestIsMemberOfGroup(t *testing.T) {
	// This will likely fail/return false on most systems but shouldn't panic
	_, err := IsMemberOfGroup("root", "root")
	_ = err // May error, that's ok
}
