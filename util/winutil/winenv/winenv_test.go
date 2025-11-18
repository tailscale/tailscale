// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winenv

import (
	"runtime"
	"testing"
)

func TestIsAppContainer(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	_ = IsAppContainer()
}
