// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"context"
	"sync"
	"testing"
)

func TestWaiterSet(t *testing.T) {
	var s waiterSet

	wantLen := func(want int, when string) {
		t.Helper()
		if got := len(s); got != want {
			t.Errorf("%s: len = %v; want %v", when, got, want)
		}
	}
	wantLen(0, "initial")
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())

	ready, cleanup := s.add(&mu, ctx)
	wantLen(1, "after add")

	select {
	case <-ready:
		t.Fatal("should not be ready")
	default:
	}
	s.wakeAll()
	<-ready

	wantLen(1, "after fire")
	cleanup()
	wantLen(0, "after cleanup")

	// And again but on an already-expired ctx.
	cancel()
	ready, cleanup = s.add(&mu, ctx)
	<-ready // shouldn't block
	cleanup()
	wantLen(0, "at end")
}
