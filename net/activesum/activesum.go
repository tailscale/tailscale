// Package activesum summarizes network activity into coarse event blocks.
package activesum

import (
	"time"
)

// Event is a coarse (if all is well, at least half-minute) period of
// network activity. Events end after a Idle time passes, or the network
// interface changes.
type Event struct {
	Start     time.Time     // start of event
	Duration  time.Duration // duration of event
	Bytes     uint64        // total rx+tx bytes during event window
	Interface string        // network interface used for event
}

// Idle is the amount of time without data that marks the end of an event.
const Idle = 30 * time.Second

// ActiveSum stores activity summary state and generates Events.
type ActiveSum struct {
	// EventFunc is used to deliver complete Events.
	EventFunc func(ev Event)

	// Current event details.
	start time.Time     // beginning of current event
	last  time.Duration // nanos beyond start when last event was recorded
	bytes uint64        // total rx+tx bytes so far
	iface string        // network interface of current event
}

// Variables for testing.
var timeNow = time.Now
var timeSince = time.Since

// Record records bytes transferred.
func (a *ActiveSum) Record(bytes uint64, iface string) {
	if bytes == 0 {
		return
	}

	// The function time.Since is faster than a typical time.Now call
	// because a.start includes monotonic time, so it uses a fast path
	// in the runtime that does clock_gettime via VDSO on linux.
	since := timeSince(a.start)

	// Clear previous event if Idle has passed or interface changed.
	if a.start.IsZero() || a.iface != iface || (since-a.last) > Idle {
		a.recordEvent()

		// Calls to time.Now are relatively slow (in per-packet terms), but
		// we only call it once per event, which lasts at least Idle.
		a.start = timeNow()
		a.iface = iface
		a.bytes = 0
		since = 0
	}

	a.bytes += bytes
	a.last = since
}

func (a *ActiveSum) recordEvent() {
	if a.start.IsZero() {
		return
	}
	a.EventFunc(Event{
		Start:     a.start,
		Duration:  a.last,
		Bytes:     a.bytes,
		Interface: a.iface,
	})
}

// Close stops ActiveSum and records any remaining Event.
func (a *ActiveSum) Close() {
	a.recordEvent()
	a.start = time.Time{}
}
