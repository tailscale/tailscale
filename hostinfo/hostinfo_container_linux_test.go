// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && ts_package_container

package hostinfo

import (
	"testing"
)

func TestInContainer(t *testing.T) {
	if got := inContainer(); !got.EqualBool(true) {
		t.Error(got)
	}
}
