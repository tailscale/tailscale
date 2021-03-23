// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syncs

import (
	"context"
	"testing"
)

func TestWaitGroupChan(t *testing.T) {
	wg := NewWaitGroupChan()

	wantNotDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
			t.Fatal("done too early")
		default:
		}
	}

	wantDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
		default:
			t.Fatal("expected to be done")
		}
	}

	wg.Add(2)
	wantNotDone()

	wg.Decr()
	wantNotDone()

	wg.Decr()
	wantDone()
	wantDone()
}

func TestClosedChan(t *testing.T) {
	ch := ClosedChan()
	for i := 0; i < 2; i++ {
		select {
		case <-ch:
		default:
			t.Fatal("not closed")
		}
	}
}

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)
	s.Acquire()
	if !s.TryAcquire() {
		t.Fatal("want true")
	}
	if s.TryAcquire() {
		t.Fatal("want false")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.AcquireContext(ctx) {
		t.Fatal("want false")
	}
	s.Release()
	if !s.AcquireContext(context.Background()) {
		t.Fatal("want true")
	}
	s.Release()
	s.Release()
}
