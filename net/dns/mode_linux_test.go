// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package dns

import (
	"sync"
	"testing"
)
func TestCurrentDNSModeCache(t *testing.T) {
	currentModeMu = sync.Mutex{}
	currentMode = ""
	currentModeSet = false
	SetCurrentDNSMode("direct")
	if got := CurrentDNSMode(); got != "direct" {
		t.Fatalf("CurrentDNSMode=%q, want direct", got)
	}
	if got := CurrentDNSMode(); got != "direct" {
		t.Fatalf("cached value changed: %q", got)
	}
}

func TestSetCurrentDNSModeOnce(t *testing.T) {
	currentModeMu = sync.Mutex{}
	currentMode = ""
	currentModeSet = false
	SetCurrentDNSMode("direct")
	SetCurrentDNSMode("systemd-resolved")
	if got := CurrentDNSMode(); got != "systemd-resolved" {
		t.Fatalf("CurrentDNSMode=%q, want systemd-resolved", got)
	}
}