// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netkernelconf

import "testing"

func TestCheckUDPGROForwarding(t *testing.T) {
	_, _ = CheckUDPGROForwarding()
	// Just verify it doesn't panic
}

func TestCheckIPForwarding(t *testing.T) {
	_, _ = CheckIPForwarding()
	// Just verify it doesn't panic
}
