// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"os"
	"strconv"
	"testing"
)

// Test the default MTU in the presence of various envknobs.
func TestDefaultTunMTU(t *testing.T) {
	// Save and restore the envknobs we will be changing.

	// TS_DEBUG_MTU sets the MTU to a specific value.
	defer os.Setenv("TS_DEBUG_MTU", os.Getenv("TS_DEBUG_MTU"))
	os.Setenv("TS_DEBUG_MTU", "")

	// TS_DEBUG_ENABLE_PMTUD enables path MTU discovery.
	defer os.Setenv("TS_DEBUG_ENABLE_PMTUD", os.Getenv("TS_DEBUG_ENABLE_PMTUD"))
	os.Setenv("TS_DEBUG_ENABLE_PMTUD", "")

	// With no MTU envknobs set, we should get the conservative MTU.
	if DefaultTUNMTU() != safeTUNMTU {
		t.Errorf("default TUN MTU = %d, want %d", DefaultTUNMTU(), safeTUNMTU)
	}

	// If set, TS_DEBUG_MTU should set the MTU.
	mtu := maxTUNMTU - 1
	os.Setenv("TS_DEBUG_MTU", strconv.Itoa(int(mtu)))
	if DefaultTUNMTU() != mtu {
		t.Errorf("default TUN MTU = %d, want %d, TS_DEBUG_MTU ignored", DefaultTUNMTU(), mtu)
	}

	// MTU should be clamped to maxTunMTU.
	mtu = maxTUNMTU + 1
	os.Setenv("TS_DEBUG_MTU", strconv.Itoa(int(mtu)))
	if DefaultTUNMTU() != maxTUNMTU {
		t.Errorf("default TUN MTU = %d, want %d, clamping failed", DefaultTUNMTU(), maxTUNMTU)
	}

	// If PMTUD is enabled, the MTU should default to the safe MTU, but only
	// if the user hasn't requested a specific MTU.
	//
	// TODO: When PMTUD is generating PTB responses, this will become the
	// largest MTU we probe.
	os.Setenv("TS_DEBUG_MTU", "")
	os.Setenv("TS_DEBUG_ENABLE_PMTUD", "true")
	if DefaultTUNMTU() != safeTUNMTU {
		t.Errorf("default TUN MTU = %d, want %d", DefaultTUNMTU(), safeTUNMTU)
	}
	// TS_DEBUG_MTU should take precedence over TS_DEBUG_ENABLE_PMTUD.
	mtu = WireToTUNMTU(MaxPacketSize - 1)
	os.Setenv("TS_DEBUG_MTU", strconv.Itoa(int(mtu)))
	if DefaultTUNMTU() != mtu {
		t.Errorf("default TUN MTU = %d, want %d", DefaultTUNMTU(), mtu)
	}
}

// Test the conversion of wire MTU to/from Tailscale TUN MTU corner cases.
func TestMTUConversion(t *testing.T) {
	tests := []struct {
		w WireMTU
		t TUNMTU
	}{
		{w: 0, t: 0},
		{w: wgHeaderLen - 1, t: 0},
		{w: wgHeaderLen, t: 0},
		{w: wgHeaderLen + 1, t: 1},
		{w: 1360, t: 1280},
		{w: 1500, t: 1420},
		{w: 9000, t: 8920},
	}

	for _, tt := range tests {
		m := WireToTUNMTU(tt.w)
		if m != tt.t {
			t.Errorf("conversion of wire MTU %v to TUN MTU = %v, want %v", tt.w, m, tt.t)
		}
	}

	tests2 := []struct {
		t TUNMTU
		w WireMTU
	}{
		{t: 0, w: wgHeaderLen},
		{t: 1, w: wgHeaderLen + 1},
		{t: 1280, w: 1360},
		{t: 1420, w: 1500},
		{t: 8920, w: 9000},
	}

	for _, tt := range tests2 {
		m := TUNToWireMTU(tt.t)
		if m != tt.w {
			t.Errorf("conversion of TUN MTU %v to wire MTU = %v, want %v", tt.t, m, tt.w)
		}
	}
}
