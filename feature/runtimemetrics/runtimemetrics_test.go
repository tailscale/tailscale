// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package runtimemetrics

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestSetEnabledEndToEnd(t *testing.T) {
	synctest.Test(t, syncTestSetEnabledEndToEnd)
}

func syncTestSetEnabledEndToEnd(t *testing.T) {
	getPoller := func() *poller {
		setEnabledMu.Lock()
		defer setEnabledMu.Unlock()
		return runningPoller
	}

	if p := getPoller(); p != nil {
		t.Fatalf("runningPoller not nil at test start: %p", p)
	}
	t.Cleanup(func() { setEnabled(false) })

	// disabled -> enabled: starts a poller that immediately polls.
	setEnabled(true)
	p1 := getPoller()
	if p1 == nil {
		t.Fatal("runningPoller nil after setEnabled(true)")
	}

	// Wait for the immediate pollAndEmit to finish and the goroutine to
	// block on the ticker.
	synctest.Wait()

	// Lazy metric registration must have happened and values must be set
	// from a real runtime/metrics read. Both currently-tracked metrics
	// (heap objects + total memory) are always >0 in a running Go process.
	for i, cm := range clientmetrics {
		if cm.metric == nil {
			t.Fatalf("clientmetrics[%d] (%s) metric nil after first poll", i, cm.sampleName)
		}
		if got := cm.metric.Value(); got <= 0 {
			t.Errorf("clientmetrics[%d] (%s) = %d after first poll, want > 0",
				i, cm.clientmetricName, got)
		}
	}

	// setEnabled(true) while enabled is idempotent: same poller instance.
	setEnabled(true)
	if p := getPoller(); p != p1 {
		t.Fatalf("setEnabled(true) replaced poller: got %p, want %p", p, p1)
	}

	// Overwrite each gauge with a sentinel so we can prove the next tick
	// re-reads runtime values.
	const sentinel = int64(-1)
	for _, cm := range clientmetrics {
		cm.metric.Set(sentinel)
	}

	// Advance virtual time one tick. The poller's ticker fires and pollAndEmit
	// runs again.
	time.Sleep(pollInterval)
	synctest.Wait()

	for i, cm := range clientmetrics {
		if got := cm.metric.Value(); got == sentinel {
			t.Errorf("clientmetrics[%d] (%s) still sentinel %d after tick; ticker did not fire",
				i, cm.clientmetricName, got)
		} else if got <= 0 {
			t.Errorf("clientmetrics[%d] (%s) = %d after tick, want > 0",
				i, cm.clientmetricName, got)
		}
	}

	// enabled -> disabled: stops the poller; wg.Wait inside close() means
	// the goroutine has exited by the time setEnabled returns.
	setEnabled(false)
	if p := getPoller(); p != nil {
		t.Fatalf("runningPoller %p still set after setEnabled(false)", p)
	}

	// After disabling, gauges must remain at their last polled values
	// indefinitely (no further ticks should overwrite them).
	for _, cm := range clientmetrics {
		cm.metric.Set(sentinel)
	}
	time.Sleep(10 * pollInterval)
	synctest.Wait()
	for i, cm := range clientmetrics {
		if got := cm.metric.Value(); got != sentinel {
			t.Errorf("clientmetrics[%d] (%s) = %d after disabling; poller goroutine still running?",
				i, cm.clientmetricName, got)
		}
	}

	// disabled -> disabled: still a no-op.
	setEnabled(false)
	if p := getPoller(); p != nil {
		t.Fatalf("runningPoller %p set after second setEnabled(false)", p)
	}

	// Re-enable creates a fresh poller, not the closed one.
	setEnabled(true)
	synctest.Wait()
	p2 := getPoller()
	if p2 == nil {
		t.Fatal("runningPoller nil on re-enable")
	}
	if p2 == p1 {
		t.Fatal("re-enable returned previously-closed poller")
	}
}
