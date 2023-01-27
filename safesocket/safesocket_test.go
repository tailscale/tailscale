// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import "testing"

func TestLocalTCPPortAndToken(t *testing.T) {
	// Just test that it compiles for now (is available on all platforms).
	port, token, err := LocalTCPPortAndToken()
	t.Logf("got %v, %s, %v", port, token, err)
}
