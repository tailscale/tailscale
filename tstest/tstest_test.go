// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
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

func TestGetSeed(t *testing.T) {
	t.Setenv("TS_TEST_SEED", "1234")
	if got, want := GetSeed(t), int64(1234); got != want {
		t.Errorf("GetSeed = %v; want %v", got, want)
	}
}
