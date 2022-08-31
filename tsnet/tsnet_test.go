// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsnet

import "testing"

// TestListener_Server ensures that the listener type always keeps the Server
// method, which is used by some external applications to identify a tsnet.Listener
// from other net.Listeners, as well as access the underlying Server.
func TestListener_Server(t *testing.T) {
	s := &Server{}
	ln := listener{s: s}
	if ln.Server() != s {
		t.Errorf("listener.Server() returned %v, want %v", ln.Server(), s)
	}
}
