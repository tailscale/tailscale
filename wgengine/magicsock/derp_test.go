// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"testing"

	"tailscale.com/net/netcheck"
)

func CheckDERPHeuristicTimes(t *testing.T) {
	if netcheck.PreferredDERPFrameTime <= frameReceiveRecordRate {
		t.Errorf("PreferredDERPFrameTime too low; should be at least frameReceiveRecordRate")
	}
}
