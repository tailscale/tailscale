// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	// The VMs' artifacts are built once per process, for all its tests, so
	// they live outside any one test's TempDir; remove them here.
	if artifacts.tmpDir != "" {
		os.RemoveAll(artifacts.tmpDir)
	}
	os.Exit(code)
}
