// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vms

import (
	"testing"
)

func TestDistrosGotLoaded(t *testing.T) {
	if len(Distros) == 0 {
		t.Fatal("no distros were loaded")
	}
}
