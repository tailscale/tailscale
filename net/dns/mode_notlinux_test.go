// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package dns

import "testing"

func TestCurrentDNSModeStub(t *testing.T) {
	if CurrentDNSMode() != "" {
		t.Errorf("expected empty DNS mode")
	}
	SetCurrentDNSMode("direct")
	if CurrentDNSMode() != "" {
		t.Errorf("SetCurrentDNSMode should have no effect")
	}
}
