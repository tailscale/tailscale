// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tstun

import (
	"os"
	"strconv"
	"testing"
)

func TestInitialMTU(t *testing.T) {
	// Save and restore the envknobs we will be changing

	// The user can specify the MTU with this envknob
	ts_debug_mtu := os.Getenv("TS_DEBUG_MTU")
	defer os.Setenv("TS_DEBUG_MTU", ts_debug_mtu)

	// The intention is that PMTUD will be enabled by default someday
	ts_debug_pmtud := os.Getenv("TS_DEBUG_PMTUD")
	defer os.Setenv("TS_DEBUG_PMTUD", ts_debug_pmtud)

	os.Setenv("TS_DEBUG_MTU", "")
	os.Setenv("TS_DEBUG_PMTUD", "")

	// With no MTU envknobs, we should get the conservative MTU
	if DefaultTunMTU() != safeTunMTU {
		t.Errorf("DefaultTunMTU() = %d, want %v", DefaultTunMTU(), safeTunMTU)
	}

	// TS_DEBUG_MTU should take precedence over every other setting
	os.Setenv("TS_DEBUG_MTU", "10000")
	if DefaultTunMTU() != 10000 {
		t.Errorf("DefaultTunMTU() = %d, want 10000, TS_DEBUG_MTU ignored", DefaultTunMTU())
	}

	// MTU should be clamped to maxTunMTU
	os.Setenv("TS_DEBUG_MTU", "123456789")
	if DefaultTunMTU() != maxTunMTU {
		t.Errorf("DefaultTunMTU() = %d, want %d, clamping failed", DefaultTunMTU(), maxTunMTU)
	}

	// If PMTUD is enabled, the MTU should default to the largest
	// probed MTU, but only if the user hasn't set an MTU
	os.Setenv("TS_DEBUG_MTU", "")
	os.Setenv("TS_DEBUG_PMTUD", "true")
	if DefaultTunMTU() != WireToTunMTU(MaxProbedWireMTU) {
		t.Errorf("DefaultTunMTU() = %d, want %v", DefaultTunMTU(), WireToTunMTU(MaxProbedWireMTU))
	}
	// TS_DEBUG_MTU should take precedence over TS_DEBUG_PMTUD
	mtu := WireToTunMTU(MaxProbedWireMTU + 1000)
	os.Setenv("TS_DEBUG_MTU", strconv.Itoa(int(mtu)))
	if DefaultTunMTU() != mtu {
		t.Errorf("DefaultTunMTU() = %d, want %v", DefaultTunMTU(), mtu)
	}
}

// Test the wire to Tailscale TUN MTU conversion corner cases
func TestMTUConversion(t *testing.T) {
	tests := []struct {
		w WireMTU
		t TunMTU
	}{
		{w: 0, t: 0},
		{w: wgHeaderLen, t: 0},
		{w: wgHeaderLen + 1, t: 1},
		{w: 1360, t: 1280},
		{w: 1500, t: 1420},
		{w: 9000, t: 8920},
	}

	for _, tt := range tests {
		m := WireToTunMTU(tt.w)
		if m != tt.t {
			t.Errorf("conversion of wire MTU %v to TUN MTU = %v, want %v", tt.w, m, tt.t)
		}
	}
	for _, tt := range tests {
		m := WireToTunMTU(tt.w)
		if m != tt.t {
			t.Errorf("conversion of wire MTU %v to TUN MTU = %v, want %v", tt.w, m, tt.t)
		}
	}
}
