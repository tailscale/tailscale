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

	// With b.mu free and no subsystems registered, the probe returns
	// immediately and must not report a deadlock.
	b.runDeadlockProbe()
	done()
}

// TestDeadlockWatcherObserve checks the pure accounting: only wakeups that
// arrive at a plausible cadence count toward the timeout, and gaps during
// which the process was not running are skipped without resetting progress.
func TestDeadlockWatcherObserve(t *testing.T) {
	const tick = deadlockTickInterval
	type step struct {
		gap  time.Duration // time since the previous observation
		want bool          // whether observe should report a deadlock
	}
	repeat := func(n int, gap time.Duration) []step {
		var steps []step
		for range n {
			steps = append(steps, step{gap: gap})
		}
		return steps
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name:  "steady_ticks_fire_at_timeout",
			steps: append(repeat(29, tick), step{gap: tick, want: true}),
		},
		{
			name: "late_ticks_count_in_full",
			// Ticks 50% late still prove the process ran for that long.
			steps: append(repeat(19, tick*3/2), step{gap: tick * 3 / 2, want: true}),
		},
		{
			name: "freeze_is_skipped_not_counted",
			// 20s stuck, then an 8 minute freeze that must not count as
			// stuck time, then 10 more seconds stuck: fires at 30s of
			// running time, not on the first tick after the thaw.
			steps: append(append(repeat(20, tick), step{gap: 8 * time.Minute}), append(repeat(9, tick), step{gap: tick, want: true})...),
		},
		{
			name: "freeze_alone_never_fires",
			// A single 30 second timer would have fired on any of these.
			steps: append(repeat(3, tick), repeat(5, time.Hour)...),
		},
		{
			name: "gap_at_threshold_counts",
			// Exactly deadlockMaxTickGap is still a plausible late wakeup.
			steps: append(repeat(5, deadlockMaxTickGap), step{gap: deadlockMaxTickGap, want: true}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			w := &deadlockWatcher{last: now}
			for i, s := range tt.steps {
				now = now.Add(s.gap)
				if got := w.observe(now); got != s.want {
					t.Fatalf("step %d (gap %v): observe = %v, want %v (running=%v)", i, s.gap, got, s.want, w.running)
				}
			}
		})
	}
}

// TestDeadlockWatcherRun drives the watcher goroutine with a fake clock and
// checks that a freeze (a large jump of the clock between ticks) does not
// make it report, while enough on-schedule ticks do.
func TestDeadlockWatcherRun(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)})
	b := &LocalBackend{clock: clock}
	w := b.newDeadlockWatcher()

	reported := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go w.run(stop, func() { close(reported) })

	// waitTicks blocks until the watcher has processed at least n wakeups.
	waitTicks := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for w.ticks.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("watcher processed %d ticks, want at least %d", w.ticks.Load(), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	assertNotReported := func(what string) {
		t.Helper()
		select {
		case <-reported:
			t.Fatalf("watcher reported a deadlock %s", what)
		default:
		}
	}

	// 10 seconds of on-schedule ticks.
	var ticks int64
	for range 10 {
		clock.Advance(deadlockTickInterval)
		ticks++
		waitTicks(ticks)
	}
	assertNotReported("after 10s")

	// Freeze for eight minutes. A plain 30s timer would fire here.
	clock.Advance(8 * time.Minute)
	ticks++
	waitTicks(ticks)
	assertNotReported("right after an 8 minute freeze")

	// 19 more seconds of running time, for 29 total: still not stuck for
	// long enough.
	for range 19 {
		clock.Advance(deadlockTickInterval)
		ticks++
		waitTicks(ticks)
	}
	assertNotReported("after 29s of running time")

	// The 30th second of running time reports.
	clock.Advance(deadlockTickInterval)
	select {
	case <-reported:
	case <-time.After(10 * time.Second):
		t.Fatalf("watcher did not report after %v of running time (running=%v)", deadlockTimeout, w.running)
	}
}

// TestDeadlockWatcherStop checks that closing stop ends the watcher without
// it reporting, which is how runDeadlockProbe cancels it once the probed
// locks are acquired.
func TestDeadlockWatcherStop(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(123, 0)})
	b := &LocalBackend{clock: clock}
	w := b.newDeadlockWatcher()

	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		w.run(stop, func() { t.Error("watcher reported a deadlock after stop") })
		close(exited)
	}()
	close(stop)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("watcher did not exit after stop was closed")
	}
}
