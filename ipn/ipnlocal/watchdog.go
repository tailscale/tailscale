// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"log"
	"runtime"
	"sync/atomic"
	"time"

	"tailscale.com/tstime"
)

// deadlockProbeDelay is how long a watched call must be in flight before we
// start probing locks to check for a deadlock. Calls that complete sooner do
// not trigger any probing.
const deadlockProbeDelay = 5 * time.Second

// deadlockTimeout is how long the probed locks may be held, measured only
// over time in which this process was demonstrably running (see
// [deadlockWatcher]), before we declare a deadlock and panic with goroutine
// stacks.
const deadlockTimeout = 30 * time.Second

// deadlockTickInterval is how often the [deadlockWatcher] wakes up to check
// that the process is actually being scheduled.
const deadlockTickInterval = time.Second

// deadlockMaxTickGap is the longest interval between two consecutive
// [deadlockWatcher] wakeups that still counts as time the process was running.
// A longer gap means the process was not being scheduled at all (a frozen
// container or VM, a suspended host whose guest monotonic clock kept
// advancing, or extreme CPU starvation), so that time is not evidence of a
// deadlock and is not counted toward [deadlockTimeout].
const deadlockMaxTickGap = 5 * deadlockTickInterval

// CheckDeadlocks schedules a delayed deadlock probe and returns a function to
// call when the operation being watched is done. Callers typically use it as
// "defer b.CheckDeadlocks()()" to bracket a region of code that should not
// take more than [deadlockProbeDelay].
//
// This is a backstop for detecting and debugging deadlocks in the process, replacing
// the earlier watchdogEngine removed in 2b338dd6a8dbd.
func (b *LocalBackend) CheckDeadlocks() (done func()) {
	// Bump the in-flight count. If a watched region is already open, the
	// probe timer is already armed, so the bump is all we need to do: the
	// matching doneDeadlockCheck will decrement when this caller returns and
	// only the last one out will stop the timer.
	if b.deadlockChecksInFlight.Add(1) != 1 {
		return b.doneDeadlockCheck
	}

	// Fast path to avoid the deadlockTimerMu+Timer.Reset cost when
	// CheckDeadlocks is called many times per second by non-overlapping
	// callers: re-arm the probe timer at most once per wall-clock second.
	// We use a unix-seconds timestamp (+1 so 0 can mean "never") and a CAS
	// so that only one caller per second proceeds to touch the timer; the
	// rest return early.
	nowUnix := tstime.DefaultClock{Clock: b.Clock()}.Now().Unix() + 1
	lastUnix := b.lastDeadlockCheckUnix.Load()
	if lastUnix == nowUnix || !b.lastDeadlockCheckUnix.CompareAndSwap(lastUnix, nowUnix) {
		return b.doneDeadlockCheck
	}

	// Slow path: (re)arm the probe timer. Lazily create it on first use.
	b.deadlockTimerMu.Lock()
	defer b.deadlockTimerMu.Unlock()

	t := b.deadlockProbeTimer
	if t == nil {
		t = time.AfterFunc(deadlockProbeDelay, b.runDeadlockProbe)
		b.deadlockProbeTimer = t
	} else {
		t.Reset(deadlockProbeDelay)
	}
	return b.doneDeadlockCheck
}

func (b *LocalBackend) doneDeadlockCheck() {
	switch n := b.deadlockChecksInFlight.Add(-1); {
	case n > 0:
		return
	case n < 0:
		panic("ipnlocal: doneDeadlockCheck called without matching CheckDeadlocks")
	}

	b.deadlockTimerMu.Lock()
	defer b.deadlockTimerMu.Unlock()
	if b.deadlockProbeTimer == nil {
		return
	}
	b.deadlockProbeTimer.Stop()
}

func (b *LocalBackend) runDeadlockProbe() {
	b.deadlockTimerMu.Lock()
	defer b.deadlockTimerMu.Unlock()

	if b.deadlockChecksInFlight.Load() == 0 {
		return
	}

	// Watch the clock in a separate goroutine while we block on the probed
	// locks below. If the probes all return, closing stop ends the watcher
	// before it can report anything.
	stop := make(chan struct{})
	defer close(stop)
	go b.newDeadlockWatcher().run(stop, b.reportDeadlock)

	b.probeLocks()
}

// deadlockWatcher decides when a stuck lock probe has been stuck long enough
// to count as a deadlock. It accumulates only time during which this process
// was demonstrably running, as observed by being woken by a periodic ticker
// at roughly the expected cadence.
//
// It exists instead of a plain time.AfterFunc(deadlockTimeout, ...) because a
// timer measures the monotonic clock alone, and that clock keeps advancing
// while a container or VM is frozen. A single 30 second timer armed just
// before an eight minute freeze fires the instant the process thaws, before
// the goroutines holding the probed locks have had a chance to run again.
// That produced a spurious watchdog panic whose stack dump looked exactly
// like a deadlock. Counting only the intervals in which the watcher was woken
// on schedule ties the timeout to the process running, not to the clock.
type deadlockWatcher struct {
	clock   tstime.Clock
	ticker  tstime.TickerController
	tickCh  <-chan time.Time
	last    time.Time     // when observe was last called
	running time.Duration // accumulated time the process was known to be running

	// ticks counts wakeups the watcher has processed, whether or not they
	// counted toward running. It exists so tests can synchronize with the
	// watcher goroutine.
	ticks atomic.Int64
}

// newDeadlockWatcher returns a watcher whose ticker is already running, so the
// caller may start [deadlockWatcher.run] in a new goroutine without racing
// against the ticker's creation.
func (b *LocalBackend) newDeadlockWatcher() *deadlockWatcher {
	clock := tstime.DefaultClock{Clock: b.Clock()}
	w := &deadlockWatcher{clock: clock, last: clock.Now()}
	w.ticker, w.tickCh = clock.NewTicker(deadlockTickInterval)
	return w
}

// observe records that the watcher was woken at now and reports whether the
// probed locks have now been held for [deadlockTimeout] of running time.
//
// Gaps longer than [deadlockMaxTickGap] since the previous observation are
// time in which the process was not running at all, so they are ignored
// rather than counted. They do not reset the accumulated time either: a
// process that was stuck for 20 seconds, frozen for 8 minutes, and then stuck
// for another 10 seconds after thawing really has been stuck for 30 seconds
// of running time.
func (w *deadlockWatcher) observe(now time.Time) (deadlocked bool) {
	gap := now.Sub(w.last)
	w.last = now
	if gap > deadlockMaxTickGap {
		return false
	}
	w.running += gap
	return w.running >= deadlockTimeout
}

// run wakes up every [deadlockTickInterval] until stop is closed or observe
// reports a deadlock, in which case it calls report.
func (w *deadlockWatcher) run(stop <-chan struct{}, report func()) {
	defer w.ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-w.tickCh:
		}
		// Read the clock rather than using the tick's value. When a tick is
		// delivered late, the runtime sends the time the tick was scheduled
		// for, not the time it was actually delivered, which would hide
		// exactly the gaps we are looking for.
		deadlocked := w.observe(w.clock.Now())
		w.ticks.Add(1)
		if deadlocked {
			report()
			return
		}
	}
}

func (b *LocalBackend) probeLocks() {
	b.probeLocalBackendLock()

	sys := b.sys
	if sys == nil {
		return
	}
	if bus, ok := sys.Bus.GetOK(); ok && bus != nil {
		bus.ProbeLocks()
	}
	if dialer, ok := sys.Dialer.GetOK(); ok && dialer != nil {
		dialer.ProbeLocks()
	}
	if dm, ok := sys.DNSManager.GetOK(); ok && dm != nil {
		dm.ProbeLocks()
	}
	if e, ok := sys.Engine.GetOK(); ok && e != nil {
		e.ProbeLocks()
	}
	if nm, ok := sys.NetMon.GetOK(); ok && nm != nil {
		nm.ProbeLocks()
	}
	if mc, ok := sys.MagicSock.GetOK(); ok && mc != nil {
		mc.ProbeLocks()
	}
	if tun, ok := sys.Tun.GetOK(); ok && tun != nil {
		tun.ProbeLocks()
	}
	if ht, ok := sys.HealthTracker.GetOK(); ok && ht != nil {
		ht.ProbeLocks()
	}
}

func (b *LocalBackend) probeLocalBackendLock() {
	b.mu.Lock()
	defer b.mu.Unlock()
}

func (b *LocalBackend) reportDeadlock() {
	logf := b.logf
	if logf == nil {
		logf = log.Printf
	}
	logf("ipnlocal watchdog goroutine stacks:\n%s", goroutineStacks())
	panic("ipnlocal: watchdog timeout")
}

func goroutineStacks() []byte {
	buf := make([]byte, 256<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
