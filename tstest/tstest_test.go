// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"runtime"
	"testing"
)

func TestReplace(t *testing.T) {
	before := "before"
	done := false
	t.Run("replace", func(t *testing.T) {
		Replace(t, &before, "after")
		if before != "after" {
			t.Errorf("before = %q; want %q", before, "after")
		}
		done = true
	})
	if !done {
		t.Fatal("subtest didn't run")
	}
	if before != "before" {
		t.Errorf("before = %q; want %q", before, "before")
	}
}

func TestKernelVersion(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
	default:
		t.Skipf("skipping test on %s", runtime.GOOS)
	}

	major, minor, patch := KernelVersion()
	if major == 0 && minor == 0 && patch == 0 {
		t.Fatal("KernelVersion returned (0, 0, 0); expected valid version")
	}
	t.Logf("Kernel version: %d.%d.%d", major, minor, patch)
}
