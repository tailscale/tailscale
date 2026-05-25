// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package progresstracking

import "testing"

func TestTracker(t *testing.T) {
	tracker := &Tracker{}
	if tracker == nil {
		t.Fatal("Tracker is nil")
	}
}
