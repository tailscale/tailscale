// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package coalescedop_test

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/util/coalescedop"
)

func TestSingleCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		done := make(chan struct{})
		op := coalescedop.New(func() {
			n.Add(1)
			close(done)
		})
		op.Do()
		<-done
		if got := n.Load(); got != 1 {
			t.Errorf("n=%d; want 1", got)
		}
	})
}

func TestCoalescesWhileRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		release := make(chan struct{})
		op := coalescedop.New(func() {
			n.Add(1)
			<-release
		})

		// Start the first execution; it blocks on release.
		op.Do()
		// synctest.Test advances the fake clock only once all
		// goroutines in the bubble are blocked, so this Sleep
		// reliably waits for the goroutine to be parked on <-release.
		time.Sleep(time.Millisecond)

		// Request several more while the first is running.
		op.Do()
		op.Do()
		op.Do()

		// Release the first execution.
		release <- struct{}{}
		time.Sleep(time.Millisecond) // wait for coalesced run to block on <-release

		// Release the second (coalesced) execution.
		release <- struct{}{}
		time.Sleep(time.Millisecond) // wait for run() to finish

		if got := n.Load(); got != 2 {
			t.Errorf("n=%d; want 2 (one original + one coalesced)", got)
		}
	})
}

func TestNoPendingIfNotRequested(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		done := make(chan struct{}, 1)
		op := coalescedop.New(func() {
			n.Add(1)
			done <- struct{}{}
		})

		op.Do()
		<-done
		time.Sleep(time.Millisecond) // wait for run() to finish

		// No more executions should happen.
		if got := n.Load(); got != 1 {
			t.Errorf("n=%d; want 1", got)
		}

		// A new Do after completion should run again.
		op.Do()
		<-done
		if got := n.Load(); got != 2 {
			t.Errorf("n=%d; want 2", got)
		}
	})
}
