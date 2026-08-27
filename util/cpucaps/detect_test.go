// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_cpucaps

package cpucaps

import (
	"runtime"
	"testing"
)

func TestHostGOAMD64Level(t *testing.T) {
	got := HostGOAMD64Level()
	t.Logf("HostGOAMD64Level = %d", got)
	if runtime.GOARCH == "amd64" {
		if got < 1 || got > 4 {
			t.Errorf("got %d; want in range [1,4] on amd64", got)
		}
	} else if got != 0 {
		t.Errorf("got %d; want 0 on non-amd64", got)
	}
}

func TestCompiledGOAMD64Level(t *testing.T) {
	got := CompiledGOAMD64Level()
	t.Logf("CompiledGOAMD64Level = %d", got)
	if runtime.GOARCH == "amd64" {
		if got < 1 || got > 4 {
			t.Errorf("got %d; want in range [1,4] since test binaries have build info", got)
		}
	} else if got != 0 {
		t.Errorf("got %d; want 0 on non-amd64", got)
	}
}

func TestHostCaps(t *testing.T) {
	c := Host()
	t.Logf("Host caps = %#x (%v)", uint64(c), c)
	if c >= capMax {
		t.Errorf("unexpected bits set beyond capMax: %#x", uint64(c))
	}
	if Host() != c {
		t.Errorf("Host not stable across calls")
	}
}
