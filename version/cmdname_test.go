// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package version_test

import (
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/version"
)

// TestCmdNameFromBuildInfo asserts that CmdName recovers its result from the
// running binary's embedded Go module info (via runtime/debug.ReadBuildInfo)
// rather than returning the os.Executable-based fallback. When this test is
// run under "go test tailscale.com/version", the test binary's embedded
// build-info Path is "tailscale.com/version.test", so CmdName should return
// "version.test". The on-disk basename of the test binary (something like
// "version.test" in a go-build temp dir with random suffixes) is also
// typically "version.test", but the import-path derivation is what we care
// about: it is the only route by which a binary installed under an arbitrary
// name (e.g. "tailscaled-linux-amd64") still reports itself as "tailscaled".
func TestCmdNameFromBuildInfo(t *testing.T) {
	if got, want := version.CmdName(), "version.test"; got != want {
		t.Errorf("CmdName() = %q, want %q", got, want)
	}
}

// BenchmarkCmdName measures the cost of the public, memoized CmdName.
// After a one-time warmup (which itself does no filesystem I/O, just an
// in-memory string lookup), this should be a trivial atomic load with zero
// allocations.
func BenchmarkCmdName(b *testing.B) {
	_ = version.CmdName() // prime
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = version.CmdName()
	}
}

// TestCmdNameNoAllocs asserts that the public CmdName, once primed, performs
// no allocations. This guards against regressions that reintroduce per-call
// binary parsing.
func TestCmdNameNoAllocs(t *testing.T) {
	_ = version.CmdName() // prime
	if err := tstest.MinAllocsPerRun(t, 0, func() {
		_ = version.CmdName()
	}); err != nil {
		t.Error(err)
	}
}
