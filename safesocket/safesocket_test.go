// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import "testing"

func TestLocalTCPPortAndToken(t *testing.T) {
	// Just test that it compiles for now (is available on all platforms).
	port, token, err := LocalTCPPortAndToken()
	t.Logf("got %v, %s, %v", port, token, err)
}
