// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"path/filepath"
	"testing"
)

func TestGetNetshPath(t *testing.T) {
	ft := &firewallTweaker{
		logf: t.Logf,
	}
	path := ft.getNetshPath()
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path for netsh.exe: %q", path)
	}
}
