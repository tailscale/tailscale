// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailscale_go

package tailscaleroot

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func TestToolchainMatches(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("failed to read build info")
	}
	var tsRev string
	for _, s := range bi.Settings {
		if s.Key == "tailscale.toolchain.rev" {
			tsRev = s.Value
			break
		}
	}
	want := strings.TrimSpace(GoToolchainRev)
	if tsRev != want {
		if os.Getenv("TS_PERMIT_TOOLCHAIN_MISMATCH") == "1" {
			t.Logf("tailscale.toolchain.rev = %q, want %q; but ignoring due to TS_PERMIT_TOOLCHAIN_MISMATCH=1", tsRev, want)
			return
		}
		t.Errorf("tailscale.toolchain.rev = %q, want %q; permit with TS_PERMIT_TOOLCHAIN_MISMATCH=1", tsRev, want)
	}
}
