// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nettest contains additional test helpers related to network state
// that can't go into tstest for circular dependency reasons.
package nettest

import (
	"testing"

	"tailscale.com/net/netmon"
)

// SkipIfNoNetwork skips the test if it looks like there's no network
// access.
func SkipIfNoNetwork(t testing.TB) {
	nm := netmon.NewStatic()
	if !nm.InterfaceState().AnyInterfaceUp() {
		t.Skip("skipping; test requires network but no interface is up")
	}
}
