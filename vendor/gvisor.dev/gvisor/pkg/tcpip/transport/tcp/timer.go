// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type timerState int

const (
	// The timer is disabled.
	timerStateDisabled timerState = iota
	// The timer is enabled, but the clock timer may be set to an earlier
	// expiration time due to a previous orphaned state.
	timerStateEnabled
	// The timer is disabled, but the clock timer is enabled, which means that
	// it will cause a spurious wakeup unless the timer is enabled before the
	// clock timer fires.
	timerStateOrphaned
)

// timer is a timer implementation that reduces the interactions with the
// clock timer infrastructure by letting timers run (and potentially
// eventually expire) even if they are stopped. It makes it cheaper to
// disable/reenable timers at the expense of spurious wakes. This is useful for
// cases when the same timer is disabled/reenabled repeatedly with relatively
// long timeouts farther into the future.
//
// TCP retransmit timers benefit from this because they the timeouts are long
// (currently at least 200ms), and get disabled when acks are received, and
// reenabled when new pending segments are sent.
//
// It is advantageous to avoid interacting with the clock because it acquires
// a global mutex and performs O(log n) operations, where n is the global number
// of timers, whenever a timer is enabled or disabled, and may make a syscall.
//
// This struct is thread-compatible.
type timer struct {
	state timerState

	clock tcpip.Clock

	// target is the expiration time of the current timer. It is only
	// meaningful in the enabled state.
	target tcpip.MonotonicTime

	// clockTarget is the expiration time of the clock timer. It is
	// meaningful in the enabled and orphaned states.
	clockTarget tcpip.MonotonicTime

	// timer is the clock timer used to wait on.
	timer tcpip.Timer
}

// init initializes the timer. Once it expires, it the given waker will be
// asserted.
func (t *timer) init(clock tcpip.Clock, w *sleep.Waker) {
	t.state = timerStateDisabled
	t.clock = clock

	// Initialize a clock timer that will assert the waker, then
	// immediately stop it.
	t.timer = t.clock.AfterFunc(math.MaxInt64, func() {
		w.Assert()
	})
	t.timer.Stop()
}

// cleanup frees all resources associated with the timer.
func (t *timer) cleanup() {
	if t.timer == nil {
		// No cleanup needed.
		return
	}
	t.timer.Stop()
	*t = timer{}
}

// checkExpiration checks if the given timer has actually expired, it should be
// called whenever a sleeper wakes up due to the waker being asserted, and is
// used to check if it's a supurious wake (due to a previously orphaned timer)
// or a legitimate one.
func (t *timer) checkExpiration() bool {
	// Transition to fully disabled state if we're just consuming an
	// orphaned timer.
	if t.state == timerStateOrphaned {
		t.state = timerStateDisabled
		return false
	}

	// The timer is enabled, but it may have expired early. Check if that's
	// the case, and if so, reset the runtime timer to the correct time.
	now := t.clock.NowMonotonic()
	if now.Before(t.target) {
		t.clockTarget = t.target
		t.timer.Reset(t.target.Sub(now))
		return false
	}

	// The timer has actually expired, disable it for now and inform the
	// caller.
	t.state = timerStateDisabled
	return true
}

// disable disables the timer, leaving it in an orphaned state if it wasn't
// already disabled.
func (t *timer) disable() {
	if t.state != timerStateDisabled {
		t.state = timerStateOrphaned
	}
}

// enabled returns true if the timer is currently enabled, false otherwise.
func (t *timer) enabled() bool {
	return t.state == timerStateEnabled
}

// enable enables the timer, programming the runtime timer if necessary.
func (t *timer) enable(d time.Duration) {
	t.target = t.clock.NowMonotonic().Add(d)

	// Check if we need to set the runtime timer.
	if t.state == timerStateDisabled || t.target.Before(t.clockTarget) {
		t.clockTarget = t.target
		t.timer.Reset(d)
	}

	t.state = timerStateEnabled
}
