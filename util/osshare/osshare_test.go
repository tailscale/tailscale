// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osshare

import "testing"

func TestSetFileSharingEnabled(t *testing.T) {
	// Basic test - may not be supported on all platforms
	_ = SetFileSharingEnabled(false)
}
