// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Parse3339 is a wrapper around time.Parse(time.RFC3339, s).
func Parse3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// Parse3339B is Parse3339 but for byte slices.
func Parse3339B(b []byte) (time.Time, error) {
	var t time.Time
	if err := t.UnmarshalText(b); err != nil {
		return Parse3339(string(b)) // reproduce same error message
	}
	return t, nil
}

// ParseDuration is more expressive than [time.ParseDuration],
// also accepting 'd' (days) and 'w' (weeks) literals.
func ParseDuration(s string) (time.Duration, error) {
	for {
		end := strings.IndexAny(s, "dw")
		if end < 0 {
			break
		}
		start := end - (len(s[:end]) - len(strings.TrimRight(s[:end], "0123456789")))
		n, err := strconv.Atoi(s[start:end])
		if err != nil {
			return 0, err
		}
		hours := 24
		if s[end] == 'w' {
			hours *= 7
		}
		s = s[:start] + s[end+1:] + strconv.Itoa(n*hours) + "h"
	}
	return time.ParseDuration(s)
}

// Sleep is like [time.Sleep] but returns early upon context cancelation.
// It reports whether the full sleep duration was achieved.
func Sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// DefaultClock is a wrapper around a Clock.
// It uses StdClock by default if Clock is nil.
type DefaultClock struct{ Clock }

// TODO: We should make the methods of DefaultClock inlineable
// so that we can optimize for the common case where c.Clock == nil.

func (c DefaultClock) Now() time.Time {
	if c.Clock == nil {
		return time.Now()
	}
	return c.Clock.Now()
}
func (c DefaultClock) NewTimer(d time.Duration) (TimerController, <-chan time.Time) {
	if c.Clock == nil {
		t := time.NewTimer(d)
		return t, t.C
	}
	return c.Clock.NewTimer(d)
}
func (c DefaultClock) NewTicker(d time.Duration) (TickerController, <-chan time.Time) {
	if c.Clock == nil {
		t := time.NewTicker(d)
		return t, t.C
	}
	return c.Clock.NewTicker(d)
}
func (c DefaultClock) AfterFunc(d time.Duration, f func()) TimerController {
	if c.Clock == nil {
		return time.AfterFunc(d, f)
	}
	return c.Clock.AfterFunc(d, f)
}
func (c DefaultClock) Since(t time.Time) time.Duration {
	if c.Clock == nil {
		return time.Since(t)
	}
	return c.Clock.Since(t)
}

// Clock offers a subset of the functionality from the std/time package.
// Normally, applications will use the StdClock implementation that calls the
// appropriate std/time exported funcs. The advantage of using Clock is that
// tests can substitute a different implementation, allowing the test to control
// time precisely, something required for certain types of tests to be possible
// at all, speeds up execution by not needing to sleep, and can dramatically
// reduce the risk of flakes due to tests executing too slowly or quickly.
type Clock interface {
	// Now returns the current time, as in time.Now.
	Now() time.Time
	// NewTimer returns a timer whose notion of the current time is controlled
	// by this Clock. It follows the semantics of time.NewTimer as closely as
	// possible but is adapted to return an interface, so the channel needs to
	// be returned as well.
	NewTimer(d time.Duration) (TimerController, <-chan time.Time)
	// NewTicker returns a ticker whose notion of the current time is controlled
	// by this Clock. It follows the semantics of time.NewTicker as closely as
	// possible but is adapted to return an interface, so the channel needs to
	// be returned as well.
	NewTicker(d time.Duration) (TickerController, <-chan time.Time)
	// AfterFunc returns a ticker whose notion of the current time is controlled
	// by this Clock. When the ticker expires, it will call the provided func.
	// It follows the semantics of time.AfterFunc.
	AfterFunc(d time.Duration, f func()) TimerController
	// Since returns the time elapsed since t.
	// It follows the semantics of time.Since.
	Since(t time.Time) time.Duration
}

// TickerController offers the receivers of a time.Ticker to ensure
// compatibility with standard timers, but allows for the option of substituting
// a standard timer with something else for testing purposes.
type TickerController interface {
	// Reset follows the same semantics as with time.Ticker.Reset.
	Reset(d time.Duration)
	// Stop follows the same semantics as with time.Ticker.Stop.
	Stop()
}

// TimerController offers the receivers of a time.Timer to ensure
// compatibility with standard timers, but allows for the option of substituting
// a standard timer with something else for testing purposes.
type TimerController interface {
	// Reset follows the same semantics as with time.Timer.Reset.
	Reset(d time.Duration) bool
	// Stop follows the same semantics as with time.Timer.Stop.
	Stop() bool
}

// StdClock is a simple implementation of Clock using the relevant funcs in the
// std/time package.
type StdClock struct{}

// Now calls time.Now.
func (StdClock) Now() time.Time {
	return time.Now()
}

// NewTimer calls time.NewTimer. As an interface does not allow for struct
// members and other packages cannot add receivers to another package, the
// channel is also returned because it would be otherwise inaccessible.
func (StdClock) NewTimer(d time.Duration) (TimerController, <-chan time.Time) {
	t := time.NewTimer(d)
	return t, t.C
}

// NewTicker calls time.NewTicker. As an interface does not allow for struct
// members and other packages cannot add receivers to another package, the
// channel is also returned because it would be otherwise inaccessible.
func (StdClock) NewTicker(d time.Duration) (TickerController, <-chan time.Time) {
	t := time.NewTicker(d)
	return t, t.C
}

// AfterFunc calls time.AfterFunc.
func (StdClock) AfterFunc(d time.Duration, f func()) TimerController {
	return time.AfterFunc(d, f)
}

// Since calls time.Since.
func (StdClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}
