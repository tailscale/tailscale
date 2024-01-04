// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"testing"
)

func TestSocketMarkWorks(t *testing.T) {
	_ = socketMarkWorks()
	// we cannot actually assert whether the test runner has SO_MARK available
	// or not, as we don't know. We're just checking that it doesn't panic.
}
