// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netknob

import "testing"

func TestUDPBatchSize(t *testing.T) {
	size := UDPBatchSize()
	if size < 0 {
		t.Errorf("UDPBatchSize() = %d, want >= 0", size)
	}
}

func TestPlatformTCPKeepAlive(t *testing.T) {
	_ = PlatformTCPKeepAlive()
	// Just verify it doesn't panic
}
