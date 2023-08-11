// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package netns

import "testing"

func TestSetAndroidProtectFunc(t *testing.T) {
	// No function has previously been set.
	hasPrevProtectFunc := SetAndroidProtectFunc(func(fd int) error { return nil })

	if hasPrevProtectFunc {
		t.Fatal("SetAndroidProtectFunc returned true, should be false")
	}

	hasPrevProtectFunc = SetAndroidProtectFunc(func(fd int) error { return nil })

	if !hasPrevProtectFunc {
		t.Fatal("SetAndroidProtectFunc returned false, should be true")
	}
}
