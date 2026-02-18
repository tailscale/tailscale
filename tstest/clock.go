// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"container/heap"
	"sync"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/util/mak"
)

// ClockOpts is used to configure the initial settings for a Clock. Once the
// settings are configured as desired, call NewClock to get the resulting Clock.
type ClockOpts struct {
	// Start is the starting time for the Clock. When FollowRealTime is false,
	// Start is also the value that will be returned by the first call
	// to Clock.Now. If you are passing a value here, set an explicit
	// timezone, otherwise the test may be non-deterministic when TZ environment
	// variable is set to different values. The default time is in UTC.
	Start time.Time

	// Step is the amount of time the Clock will advance whenever Clock.Now is
	// called. If set to zero, the Clock will only advance when Clock.Advance is
	// called and/or if FollowRealTime is true.
	//
	// FollowRealTime and Step cannot be enabled at the same time.
	Step time.Duration

	// TimerChannelSize configures the maximum buffered ticks that are
	// permitted in the channel of any Timer and Ticker created by this Clock.
	// The special value 0 means to use the default of 1. The buffer may need to
	// be increased if time is advanced by more than a single tick and proper
	// functioning of the test requires that the ticks are not lost.
	TimerChannelSize int

	// FollowRealTime makes the simulated time increment along with real time.
	// It is a compromise between determinism and the difficulty of explicitly
	// managing the simulated time via Step or Clock.Advance. When
	// FollowRealTime is set, calls to Now() and PeekNow() will add the
	// elapsed real-world time to the simulated time.
	//
	// FollowRealTime and Step cannot be enabled at the same time.
	FollowRealTime bool
}

// NewClock creates a Clock with the specified settings. To create a
// Clock with only the default settings, new(Clock) is equivalent, except that
// the start time will not be computed until one of the receivers is called.
func NewClock(co ClockOpts) *Clock {
	if co.FollowRealTime && co.Step != 0 {
		panic("only one of FollowRealTime and Step are allowed in NewClock")
	}

	return newClockInternal(co, nil)
}

// newClockInternal creates a Clock with the specified settings and allows
// specifying a non-standard realTimeClock.
func newClockInternal(co ClockOpts, rtClock tstime.Clock) *Clock {
	if !co.FollowRealTime && rtClock != nil {
		panic("rtClock can only be set with FollowRealTime enabled")
	}

	if co.FollowRealTime && rtClock == nil {
		rtClock = new(tstime.StdClock)
	}

	c := &Clock{
		start:            co.Start,
		realTimeClock:    rtClock,
		step:             co.Step,
		timerChannelSize: co.TimerChannelSize,
	}
	c.init() // init now to capture the current time when co.Start.IsZero()
	return c
}

// Clock is a testing clock that advances every time its Now method is
// called, beginning at its start time. If no start time is specified using
// ClockBuilder, an arbitrary start time will be selected when the Clock is
// created and can be retrieved by calling Clock.Start().
type Clock struct {
	// start is the first value returned by Now. It must not be modified after
	// init is called.
	start time.Time

	// realTimeClock, if not nil, indicates that the Clock shall move forward
	// according to realTimeClock + the accumulated calls to Advance. This can
	// make writing tests easier that require some control over the clock but do
	// not need exact control over the clock. While step can also be used for
	// this purpose, it is harder to control how quickly time moves using step.
	realTimeClock tstime.Clock

	initOnce sync.Once
	mu       sync.Mutex

	// step is how much to advance with each Now call.
	step time.Duration
	// present is the last value returned by Now (and will be returned again by
	// PeekNow).
	present time.Time
	// realTime is the time from realTimeClock corresponding to the current
	// value of present.
	realTime time.Time
	// skipStep indicates that the next call to Now should not add step to
	// present. This occurs after initialization and after Advance.
	skipStep bool
	// timerChannelSize is the buffer size to use for channels created by
	// NewTimer and NewTicker.
	timerChannelSize int

	events eventManager
}

func (c *Clock) init() {
	c.initOnce.Do(func() {
		if c.realTimeClock != nil {
			c.realTime = c.realTimeClock.Now()
		}
		if c.start.IsZero() {
			if c.realTime.IsZero() {
				c.start = time.Now().UTC()
			} else {
				c.start = c.realTime
			}
		}
		if c.timerChannelSize == 0 {
			c.timerChannelSize = 1
		}
		c.present = c.start
		c.skipStep = true
		c.events.AdvanceTo(c.present)
	})
}

// Now returns the virtual clock's current time, and advances it
// according to its step configuration.
func (c *Clock) Now() time.Time {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()

	step := c.step
	if c.skipStep {
		step = 0
		c.skipStep = false
	}
	c.advanceLocked(rt, step)

	return c.present
}

func (c *Clock) maybeGetRealTime() time.Time {
	if c.realTimeClock == nil {
		return time.Time{}
	}
	return c.realTimeClock.Now()
}

func (c *Clock) advanceLocked(now time.Time, add time.Duration) {
	if !now.IsZero() {
		add += now.Sub(c.realTime)
		c.realTime = now
	}
	if add == 0 {
		return
	}
	c.present = c.present.Add(add)
	c.events.AdvanceTo(c.present)
}

// PeekNow returns the last time reported by Now. If Now has never been called,
// PeekNow returns the same value as GetStart.
func (c *Clock) PeekNow() time.Time {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.present
}

// Advance moves simulated time forward or backwards by a relative amount. Any
// Timer or Ticker that is waiting will fire at the requested point in simulated
// time. Advance returns the new simulated time. If this Clock follows real time
// then the next call to Now will equal the return value of Advance + the
// elapsed time since calling Advance. Otherwise, the next call to Now will
// equal the return value of Advance, regardless of the current step.
func (c *Clock) Advance(d time.Duration) time.Time {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipStep = true

	c.advanceLocked(rt, d)
	return c.present
}

// AdvanceTo moves simulated time to a new absolute value. Any Timer or Ticker
// that is waiting will fire at the requested point in simulated time. If this
// Clock follows real time then the next call to Now will equal t + the elapsed
// time since calling Advance. Otherwise, the next call to Now will equal t,
// regardless of the configured step.
func (c *Clock) AdvanceTo(t time.Time) {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipStep = true
	c.realTime = rt
	c.present = t
	c.events.AdvanceTo(c.present)
}

// GetStart returns the initial simulated time when this Clock was created.
func (c *Clock) GetStart() time.Time {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.start
}

// GetStep returns the amount that simulated time advances on every call to Now.
func (c *Clock) GetStep() time.Duration {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.step
}

// SetStep updates the amount that simulated time advances on every call to Now.
func (c *Clock) SetStep(d time.Duration) {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.step = d
}

// SetTimerChannelSize changes the channel size for any Timer or Ticker created
// in the future. It does not affect those that were already created.
func (c *Clock) SetTimerChannelSize(n int) {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timerChannelSize = n
}

// NewTicker returns a Ticker that uses this Clock for accessing the current
// time.
func (c *Clock) NewTicker(d time.Duration) (tstime.TickerController, <-chan time.Time) {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceLocked(rt, 0)
	t := &Ticker{
		nextTrigger: c.present.Add(d),
		period:      d,
		em:          &c.events,
	}
	t.init(c.timerChannelSize)
	return t, t.C
}

// NewTimer returns a Timer that uses this Clock for accessing the current
// time.
func (c *Clock) NewTimer(d time.Duration) (tstime.TimerController, <-chan time.Time) {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceLocked(rt, 0)
	t := &Timer{
		nextTrigger: c.present.Add(d),
		em:          &c.events,
	}
	t.init(c.timerChannelSize, nil)
	return t, t.C
}

// AfterFunc returns a Timer that calls f when it fires, using this Clock for
// accessing the current time.
func (c *Clock) AfterFunc(d time.Duration, f func()) tstime.TimerController {
	c.init()
	rt := c.maybeGetRealTime()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceLocked(rt, 0)
	t := &Timer{
		nextTrigger: c.present.Add(d),
		em:          &c.events,
	}
	t.init(c.timerChannelSize, f)
	return t
}

// Since subtracts specified duration from Now().
func (c *Clock) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}

// eventHandler offers a common interface for Timer and Ticker events to avoid
// code duplication in eventManager.
type eventHandler interface {
	// Fire signals the event. The provided time is written to the event's
	// channel as the current time. The return value is the next time this event
	// should fire, otherwise if it is zero then the event will be removed from
	// the eventManager.
	Fire(time.Time) time.Time
}

// event tracks details about an upcoming Timer or Ticker firing.
type event struct {
	position int       // The current index in the heap, needed for heap.Fix and heap.Remove.
	when     time.Time // A cache of the next time the event triggers to avoid locking issues if we were to get it from eh.
	eh       eventHandler
}

// eventManager tracks pending events created by Timer and Ticker. eventManager
// implements heap.Interface for efficient lookups of the next event.
type eventManager struct {
	// clock is a real time clock for scheduling events with. When clock is nil,
	// events only fire when AdvanceTo is called by the simulated clock that
	// this eventManager belongs to. When clock is not nil, events may fire when
	// timer triggers.
	clock tstime.Clock

	mu            sync.Mutex
	now           time.Time
	heap          []*event
	reverseLookup map[eventHandler]*event

	// timer is an AfterFunc that triggers at heap[0].when.Sub(now) relative to
	// the time represented by clock. In other words, if clock is real world
	// time, then if an event is scheduled 1 second into the future in the
	// simulated time, then the event will trigger after 1 second of actual test
	// execution time (unless the test advances simulated time, in which case
	// the timer is updated accordingly). This makes tests easier to write in
	// situations where the simulated time only needs to be partially
	// controlled, and the test writer wishes for simulated time to pass with an
	// offset but still synchronized with the real world.
	//
	// In the future, this could be extended to allow simulated time to run at a
	// multiple of real world time.
	timer tstime.TimerController
}

func (em *eventManager) handleTimer() {
	rt := em.clock.Now()
	em.AdvanceTo(rt)
}

// Push implements heap.Interface.Push and must only be called by heap funcs
// with em.mu already held.
func (em *eventManager) Push(x any) {
	e, ok := x.(*event)
	if !ok {
		panic("incorrect event type")
	}
	if e == nil {
		panic("nil event")
	}

	mak.Set(&em.reverseLookup, e.eh, e)
	e.position = len(em.heap)
	em.heap = append(em.heap, e)
}

// Pop implements heap.Interface.Pop and must only be called by heap funcs with
// em.mu already held.
func (em *eventManager) Pop() any {
	e := em.heap[len(em.heap)-1]
	em.heap = em.heap[:len(em.heap)-1]
	delete(em.reverseLookup, e.eh)
	return e
}

// Len implements sort.Interface.Len and must only be called by heap funcs with
// em.mu already held.
func (em *eventManager) Len() int {
	return len(em.heap)
}

// Less implements sort.Interface.Less and must only be called by heap funcs
// with em.mu already held.
func (em *eventManager) Less(i, j int) bool {
	return em.heap[i].when.Before(em.heap[j].when)
}

// Swap implements sort.Interface.Swap and must only be called by heap funcs
// with em.mu already held.
func (em *eventManager) Swap(i, j int) {
	em.heap[i], em.heap[j] = em.heap[j], em.heap[i]
	em.heap[i].position = i
	em.heap[j].position = j
}

// Reschedule adds/updates/deletes an event in the heap, whichever
// operation is applicable (use a zero time to delete).
func (em *eventManager) Reschedule(eh eventHandler, t time.Time) {
	em.mu.Lock()
	defer em.mu.Unlock()
	defer em.updateTimerLocked()

	e, ok := em.reverseLookup[eh]
	if !ok {
		if t.IsZero() {
			// eh is not scheduled and also not active, so do nothing.
			return
		}
		// eh is not scheduled but is active, so add it.
		heap.Push(em, &event{
			when: t,
			eh:   eh,
		})
		em.processEventsLocked(em.now) // This is always safe and required when !t.After(em.now).
		return
	}

	if t.IsZero() {
		// e is scheduled but not active, so remove it.
		heap.Remove(em, e.position)
		return
	}

	// e is scheduled and active, so update it.
	e.when = t
	heap.Fix(em, e.position)
	em.processEventsLocked(em.now) // This is always safe and required when !t.After(em.now).
}

// AdvanceTo updates the current time to tm and fires all events scheduled
// before or equal to tm. When an event fires, it may request rescheduling and
// the rescheduled events will be combined with the other existing events that
// are waiting, and will be run in the unified ordering. A poorly behaved event
// may theoretically prevent this from ever completing, but both Timer and
// Ticker require positive steps into the future.
func (em *eventManager) AdvanceTo(tm time.Time) {
	em.mu.Lock()
	defer em.mu.Unlock()
	defer em.updateTimerLocked()

	em.processEventsLocked(tm)
	em.now = tm
}

// Now returns the cached current time. It is intended for use by a Timer or
// Ticker that needs to convert a relative time to an absolute time.
func (em *eventManager) Now() time.Time {
	em.mu.Lock()
	defer em.mu.Unlock()
	return em.now
}

func (em *eventManager) processEventsLocked(tm time.Time) {
	for len(em.heap) > 0 && !em.heap[0].when.After(tm) {
		// Ideally some jitter would be added here but it's difficult to do so
		// in a deterministic fashion.
		em.now = em.heap[0].when

		if nextFire := em.heap[0].eh.Fire(em.now); !nextFire.IsZero() {
			em.heap[0].when = nextFire
			heap.Fix(em, 0)
		} else {
			heap.Pop(em)
		}
	}
}

func (em *eventManager) updateTimerLocked() {
	if em.clock == nil {
		return
	}
	if len(em.heap) == 0 {
		if em.timer != nil {
			em.timer.Stop()
		}
		return
	}

	timeToEvent := em.heap[0].when.Sub(em.now)
	if em.timer == nil {
		em.timer = em.clock.AfterFunc(timeToEvent, em.handleTimer)
		return
	}
	em.timer.Reset(timeToEvent)
}

// Ticker is a time.Ticker lookalike for use in tests that need to control when
// events fire. Ticker could be made standalone in future but for now is
// expected to be paired with a Clock and created by Clock.NewTicker.
type Ticker struct {
	C <-chan time.Time // The channel on which ticks are delivered.

	// em is the eventManager to be notified when nextTrigger changes.
	// eventManager has its own mutex, and the pointer is immutable, therefore
	// em can be accessed without holding mu.
	em *eventManager

	c chan<- time.Time // The writer side of C.

	mu sync.Mutex

	// nextTrigger is the time of the ticker's next scheduled activation. When
	// Fire activates the ticker, nextTrigger is the timestamp written to the
	// channel.
	nextTrigger time.Time

	// period is the duration that is added to nextTrigger when the ticker
	// fires.
	period time.Duration
}

func (t *Ticker) init(channelSize int) {
	if channelSize <= 0 {
		panic("ticker channel size must be non-negative")
	}
	c := make(chan time.Time, channelSize)
	t.c = c
	t.C = c
	t.em.Reschedule(t, t.nextTrigger)
}

// Fire triggers the ticker. curTime is the timestamp to write to the channel.
// The next trigger time for the ticker is updated to the last computed trigger
// time + the ticker period (set at creation or using Reset). The next trigger
// time is computed this way to match standard time.Ticker behavior, which
// prevents accumulation of long term drift caused by delays in event execution.
func (t *Ticker) Fire(curTime time.Time) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.nextTrigger.IsZero() {
		return time.Time{}
	}
	select {
	case t.c <- curTime:
	default:
	}
	t.nextTrigger = t.nextTrigger.Add(t.period)

	return t.nextTrigger
}

// Reset adjusts the Ticker's period to d and reschedules the next fire time to
// the current simulated time + d.
func (t *Ticker) Reset(d time.Duration) {
	if d <= 0 {
		// The standard time.Ticker requires a positive period.
		panic("non-positive period for Ticker.Reset")
	}

	now := t.em.Now()

	t.mu.Lock()
	t.resetLocked(now.Add(d), d)
	t.mu.Unlock()

	t.em.Reschedule(t, t.nextTrigger)
}

// ResetAbsolute adjusts the Ticker's period to d and reschedules the next fire
// time to nextTrigger.
func (t *Ticker) ResetAbsolute(nextTrigger time.Time, d time.Duration) {
	if nextTrigger.IsZero() {
		panic("zero nextTrigger time for ResetAbsolute")
	}
	if d <= 0 {
		panic("non-positive period for ResetAbsolute")
	}

	t.mu.Lock()
	t.resetLocked(nextTrigger, d)
	t.mu.Unlock()

	t.em.Reschedule(t, t.nextTrigger)
}

func (t *Ticker) resetLocked(nextTrigger time.Time, d time.Duration) {
	t.nextTrigger = nextTrigger
	t.period = d
}

// Stop deactivates the Ticker.
func (t *Ticker) Stop() {
	t.mu.Lock()
	t.nextTrigger = time.Time{}
	t.mu.Unlock()

	t.em.Reschedule(t, t.nextTrigger)
}

// Timer is a time.Timer lookalike for use in tests that need to control when
// events fire. Timer could be made standalone in future but for now must be
// paired with a Clock and created by Clock.NewTimer.
type Timer struct {
	C <-chan time.Time // The channel on which ticks are delivered.

	// em is the eventManager to be notified when nextTrigger changes.
	// eventManager has its own mutex, and the pointer is immutable, therefore
	// em can be accessed without holding mu.
	em *eventManager

	f func(time.Time) // The function to call when the timer expires.

	mu sync.Mutex

	// nextTrigger is the time of the ticker's next scheduled activation. When
	// Fire activates the ticker, nextTrigger is the timestamp written to the
	// channel.
	nextTrigger time.Time
}

func (t *Timer) init(channelSize int, afterFunc func()) {
	if channelSize <= 0 {
		panic("ticker channel size must be non-negative")
	}
	c := make(chan time.Time, channelSize)
	t.C = c
	if afterFunc == nil {
		t.f = func(curTime time.Time) {
			select {
			case c <- curTime:
			default:
			}
		}
	} else {
		t.f = func(_ time.Time) { afterFunc() }
	}
	t.em.Reschedule(t, t.nextTrigger)
}

// Fire triggers the ticker. curTime is the timestamp to write to the channel.
// The next trigger time for the ticker is updated to the last computed trigger
// time + the ticker period (set at creation or using Reset). The next trigger
// time is computed this way to match standard time.Ticker behavior, which
// prevents accumulation of long term drift caused by delays in event execution.
func (t *Timer) Fire(curTime time.Time) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.nextTrigger.IsZero() {
		return time.Time{}
	}
	t.nextTrigger = time.Time{}
	t.f(curTime)
	return time.Time{}
}

// Reset reschedules the next fire time to the current simulated time + d.
// Reset reports whether the timer was still active before the reset.
func (t *Timer) Reset(d time.Duration) bool {
	if d <= 0 {
		// The standard time.Timer requires a positive delay.
		panic("non-positive delay for Timer.Reset")
	}

	return t.reset(t.em.Now().Add(d))
}

// ResetAbsolute reschedules the next fire time to nextTrigger.
// ResetAbsolute reports whether the timer was still active before the reset.
func (t *Timer) ResetAbsolute(nextTrigger time.Time) bool {
	if nextTrigger.IsZero() {
		panic("zero nextTrigger time for ResetAbsolute")
	}

	return t.reset(nextTrigger)
}

// Stop deactivates the Timer. Stop reports whether the timer was active before
// stopping.
func (t *Timer) Stop() bool {
	return t.reset(time.Time{})
}

func (t *Timer) reset(nextTrigger time.Time) bool {
	t.mu.Lock()
	wasActive := !t.nextTrigger.IsZero()
	t.nextTrigger = nextTrigger
	t.mu.Unlock()

	t.em.Reschedule(t, t.nextTrigger)
	return wasActive
}
