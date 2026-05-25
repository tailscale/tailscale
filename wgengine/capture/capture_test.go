// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package capture

import "testing"

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
}

func TestCapture_Start(t *testing.T) {
	c := New()
	defer c.Close()
	
	// Basic test - should not panic
	err := c.Start("test.pcap")
	if err != nil {
		t.Logf("Start returned error (expected on some platforms): %v", err)
	}
}
