// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vms

import (
	"testing"
)

func TestDistrosGotLoaded(t *testing.T) {
	if len(Distros) == 0 {
		t.Fatal("no distros were loaded")
	}
}
