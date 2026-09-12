// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"
	"time"

	"tailscale.com/tstest"
)

// probeArmed reports whether the delayed probe timer is currently armed.
//
// It works by stopping the timer, which reports true only if it stopped an
// active timer, so it is destructive and each call must be treated as the
// last word on that particular arming.
func probeArmed(b *LocalBackend) bool {
	b.deadlockTimerMu.Lock()
	defer b.deadlockTimerMu.Unlock()
	return b.deadlockProbeTimer != nil && b.deadlockProbeTimer.Stop()
}

func TestCheckDeadlocksTimerReuse(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)})
	b := &LocalBackend{clock: clock}

	done := b.CheckDeadlocks()
	timer := b.deadlockProbeTimer
	if timer == nil {
		t.Fatal("deadlockProbeTimer is nil")
	}
	if b.deadlockTimer != nil {
		t.Fatal("deadlockTimer is non-nil before delayed probe fires")
	}
	if got := b.deadlockChecksInFlight.Load(); got != 1 {
		t.Fatalf("deadlockChecksInFlight = %v, want 1", got)
	}
	done()
	if b.deadlockChecksInFlight.Load() != 0 {
		t.Fatalf("deadlockChecksInFlight after DoneDeadlockCheck = %v, want 0", b.deadlockChecksInFlight.Load())
	}

	done = b.CheckDeadlocks()
	if b.deadlockProbeTimer != timer {
		t.Fatal("CheckDeadlocks allocated a new probe timer instead of reusing the existing one")
	}
	if got := b.deadlockChecksInFlight.Load(); got != 1 {
		t.Fatalf("deadlockChecksInFlight = %v, want 1", got)
	}

	b.runDeadlockProbe()
	if b.deadlockTimer == nil {
		t.Fatal("runDeadlockProbe did not allocate the deadlock timer")
	}
	done()
}

// TestCheckDeadlocksArmsEveryRegion verifies that opening a watched region
// always leaves a probe timer armed, including for regions that open in the
// same wall-clock second as an earlier, already-closed one. Without that, a
// region that goes on to deadlock is never probed: the in-flight count never
// returns to zero, so every later caller takes the "already open" early return
// and nothing re-arms the timer.
func TestCheckDeadlocksArmsEveryRegion(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)})
	b := &LocalBackend{clock: clock}

	// A short region that opens and closes within one second.
	b.CheckDeadlocks()()

	// A second region in that same second, which then wedges and never
	// closes. It must still be watched.
	b.CheckDeadlocks()
	if got := b.deadlockChecksInFlight.Load(); got != 1 {
		t.Fatalf("deadlockChecksInFlight = %v, want 1", got)
	}
	if !probeArmed(b) {
		t.Fatal("probe timer not armed for a region opened in the same second as an earlier one")
	}

	// A later caller arrives while the wedged region is still open. It takes
	// the "already open" path, which relies on the timer above having been
	// armed, so the watchdog must still be able to fire.
	clock.Advance(2 * time.Second)
	b.CheckDeadlocks()
	if got := b.deadlockChecksInFlight.Load(); got != 2 {
		t.Fatalf("deadlockChecksInFlight = %v, want 2", got)
	}

	// With work in flight, the probe must actually do its job.
	b.runDeadlockProbe()
	if b.deadlockTimer == nil {
		t.Fatal("runDeadlockProbe did not allocate the deadlock timer while work was in flight")
	}
}
