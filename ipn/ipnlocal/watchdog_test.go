// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestCheckDeadlocksRateLimitAndTimerReuse(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)})
	b := &LocalBackend{clock: clock}

	done := b.CheckDeadlocks()
	if b.lastDeadlockCheckUnix.Load() != 124 {
		t.Fatalf("lastDeadlockCheckUnix = %v, want 124", b.lastDeadlockCheckUnix.Load())
	}
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

	doneCh := make(chan struct{})
	go func() {
		b.CheckDeadlocks()()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatal("same-second CheckDeadlocks did not take the rate-limit fast path")
	}
	if b.deadlockProbeTimer != timer {
		t.Fatal("same-second CheckDeadlocks allocated a new probe timer")
	}

	clock.Advance(time.Second)
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
