// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package paths

import (
	"runtime"
	"testing"
)

func TestDefaultTailscaledSocket(t *testing.T) {
	path := DefaultTailscaledSocket()
	if path == "" {
		t.Error("DefaultTailscaledSocket() returned empty")
	}
}

func TestStateFile(t *testing.T) {
	path := StateFile()
	if path == "" && runtime.GOOS != "js" {
		t.Error("StateFile() returned empty")
	}
}
