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

package tcpip

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
)

// stdClock implements Clock with the time package.
//
// +stateify savable
type stdClock struct {
	// baseTime holds the time when the clock was constructed.
	//
	// This value is used to calculate the monotonic time from the time package.
	// As per https://golang.org/pkg/time/#hdr-Monotonic_Clocks,
	//
	//   Operating systems provide both a “wall clock,” which is subject to
	//   changes for clock synchronization, and a “monotonic clock,” which is not.
	//   The general rule is that the wall clock is for telling time and the
	//   monotonic clock is for measuring time. Rather than split the API, in this
	//   package the Time returned by time.Now contains both a wall clock reading
	//   and a monotonic clock reading; later time-telling operations use the wall
	//   clock reading, but later time-measuring operations, specifically
	//   comparisons and subtractions, use the monotonic clock reading.
	//
	//   ...
	//
	//   If Times t and u both contain monotonic clock readings, the operations
	//   t.After(u), t.Before(u), t.Equal(u), and t.Sub(u) are carried out using
	//   the monotonic clock readings alone, ignoring the wall clock readings. If
	//   either t or u contains no monotonic clock reading, these operations fall
	//   back to using the wall clock readings.
	//
	// Given the above, we can safely conclude that time.Since(baseTime) will
	// return monotonically increasing values if we use time.Now() to set baseTime
	// at the time of clock construction.
	//
	// Note that time.Since(t) is shorthand for time.Now().Sub(t), as per
	// https://golang.org/pkg/time/#Since.
	baseTime time.Time `state:"nosave"`

	// monotonicOffset is the offset applied to the calculated monotonic time.
	//
	// monotonicOffset is assigned maxMonotonic after restore so that the
	// monotonic time will continue from where it "left off" before saving as part
	// of S/R.
	monotonicOffset MonotonicTime `state:"nosave"`

	// monotonicMU protects maxMonotonic.
	monotonicMU  sync.Mutex `state:"nosave"`
	maxMonotonic MonotonicTime
}

// NewStdClock returns an instance of a clock that uses the time package.
func NewStdClock() Clock {
	return &stdClock{
		baseTime: time.Now(),
	}
}

var _ Clock = (*stdClock)(nil)

// Now implements Clock.Now.
func (*stdClock) Now() time.Time {
	return time.Now()
}

// NowMonotonic implements Clock.NowMonotonic.
func (s *stdClock) NowMonotonic() MonotonicTime {
	sinceBase := time.Since(s.baseTime)
	if sinceBase < 0 {
		panic(fmt.Sprintf("got negative duration = %s since base time = %s", sinceBase, s.baseTime))
	}

	monotonicValue := s.monotonicOffset.Add(sinceBase)

	s.monotonicMU.Lock()
	defer s.monotonicMU.Unlock()

	// Monotonic time values must never decrease.
	if s.maxMonotonic.Before(monotonicValue) {
		s.maxMonotonic = monotonicValue
	}

	return s.maxMonotonic
}

// AfterFunc implements Clock.AfterFunc.
func (*stdClock) AfterFunc(d time.Duration, f func()) Timer {
	return &stdTimer{
		t: time.AfterFunc(d, f),
	}
}

type stdTimer struct {
	t *time.Timer
}

var _ Timer = (*stdTimer)(nil)

// Stop implements Timer.Stop.
func (st *stdTimer) Stop() bool {
	return st.t.Stop()
}

// Reset implements Timer.Reset.
func (st *stdTimer) Reset(d time.Duration) {
	st.t.Reset(d)
}

// NewStdTimer returns a Timer implemented with the time package.
func NewStdTimer(t *time.Timer) Timer {
	return &stdTimer{t: t}
}
