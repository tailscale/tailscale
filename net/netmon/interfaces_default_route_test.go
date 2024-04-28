// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ts_macext)

package netmon

import (
	"testing"
)

func TestDefaultRouteInterface(t *testing.T) {
	// tests /proc/net/route on the local system, cannot make an assertion about
	// the correct interface name, but good as a sanity check.
	v, err := DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got %q", v)
}
