// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"log"
	"runtime"
	"time"

	"tailscale.com/tstime"
)

// deadlockProbeDelay is how long a watched call must be in flight before we
// start probing locks to check for a deadlock. Calls that complete sooner do
// not trigger any probing.
const deadlockProbeDelay = 5 * time.Second

// deadlockTimeout is how long the lock-probing goroutine is allowed to run
// before we declare a deadlock and panic with goroutine stacks. That is, it's
// the maximum total time we allow any of the probed locks to be held.
const deadlockTimeout = 30 * time.Second

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

	t := b.deadlockTimer
	if t == nil {
		t = time.AfterFunc(deadlockTimeout, b.reportDeadlock)
		b.deadlockTimer = t
	} else {
		t.Reset(deadlockTimeout)
	}
	defer t.Stop()

	b.probeLocks()
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
