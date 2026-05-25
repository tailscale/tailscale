// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proxymap

import "testing"

func TestProxyMap(t *testing.T) {
	pm := &ProxyMap{}
	if pm == nil {
		t.Fatal("ProxyMap is nil")
	}
}
