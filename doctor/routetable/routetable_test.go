// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package routetable

import "testing"

func TestGet(t *testing.T) {
	routes, err := Get(10000)
	if err != nil {
		t.Logf("Get returned error: %v", err)
	}
	_ = routes
}

func TestRouteTable(t *testing.T) {
	rt := RouteTable{}
	_ = rt.String()
}
