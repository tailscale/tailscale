// Copyright 2020 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/sync"
)

// jobInstance is a specific instance of Job.
//
// Different instances are created each time Job is scheduled so each timer has
// its own earlyReturn signal. This is to address a bug when a Job is stopped
// and reset in quick succession resulting in a timer instance's earlyReturn
// signal being affected or seen by another timer instance.
//
// Consider the following sceneario where timer instances share a common
// earlyReturn signal (T1 creates, stops and resets a Cancellable timer under a
// lock L; T2, T3, T4 and T5 are goroutines that handle the first (A), second
// (B), third (C), and fourth (D) instance of the timer firing, respectively):
//   T1: Obtain L
//   T1: Create a new Job w/ lock L (create instance A)
//   T2: instance A fires, blocked trying to obtain L.
//   T1: Attempt to stop instance A (set earlyReturn = true)
//   T1: Schedule timer (create instance B)
//   T3: instance B fires, blocked trying to obtain L.
//   T1: Attempt to stop instance B (set earlyReturn = true)
//   T1: Schedule timer (create instance C)
//   T4: instance C fires, blocked trying to obtain L.
//   T1: Attempt to stop instance C (set earlyReturn = true)
//   T1: Schedule timer (create instance D)
//   T5: instance D fires, blocked trying to obtain L.
//   T1: Release L
//
// Now that T1 has released L, any of the 4 timer instances can take L and
// check earlyReturn. If the timers simply check earlyReturn and then do
// nothing further, then instance D will never early return even though it was
// not requested to stop. If the timers reset earlyReturn before early
// returning, then all but one of the timers will do work when only one was
// expected to. If Job resets earlyReturn when resetting, then all the timers
// will fire (again, when only one was expected to).
//
// To address the above concerns the simplest solution was to give each timer
// its own earlyReturn signal.
type jobInstance struct {
	timer Timer

	// Used to inform the timer to early return when it gets stopped while the
	// lock the timer tries to obtain when fired is held (T1 is a goroutine that
	// tries to cancel the timer and T2 is the goroutine that handles the timer
	// firing):
	//   T1: Obtain the lock, then call Cancel()
	//   T2: timer fires, and gets blocked on obtaining the lock
	//   T1: Releases lock
	//   T2: Obtains lock does unintended work
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using earlyReturn to return early so that once T2 obtains
	// the lock, it will see that it is set to true and do nothing further.
	earlyReturn *bool
}

// stop stops the job instance j from firing if it hasn't fired already. If it
// has fired and is blocked at obtaining the lock, earlyReturn will be set to
// true so that it will early return when it obtains the lock.
func (j *jobInstance) stop() {
	if j.timer != nil {
		j.timer.Stop()
		*j.earlyReturn = true
	}
}

// Job represents some work that can be scheduled for execution. The work can
// be safely cancelled when it fires at the same time some "related work" is
// being done.
//
// The term "related work" is defined as some work that needs to be done while
// holding some lock that the timer must also hold while doing some work.
//
// Note, it is not safe to copy a Job as its timer instance creates
// a closure over the address of the Job.
type Job struct {
	_ sync.NoCopy

	// The clock used to schedule the backing timer
	clock Clock

	// The active instance of a cancellable timer.
	instance jobInstance

	// locker is the lock taken by the timer immediately after it fires and must
	// be held when attempting to stop the timer.
	//
	// Must never change after being assigned.
	locker sync.Locker

	// fn is the function that will be called when a timer fires and has not been
	// signaled to early return.
	//
	// fn MUST NOT attempt to lock locker.
	//
	// Must never change after being assigned.
	fn func()
}

// Cancel prevents the Job from executing if it has not executed already.
//
// Cancel requires appropriate locking to be in place for any resources managed
// by the Job. If the Job is blocked on obtaining the lock when Cancel is
// called, it will early return.
//
// Note, t will be modified.
//
// j.locker MUST be locked.
func (j *Job) Cancel() {
	j.instance.stop()

	// Nothing to do with the stopped instance anymore.
	j.instance = jobInstance{}
}

// Schedule schedules the Job for execution after duration d. This can be
// called on cancelled or completed Jobs to schedule them again.
//
// Schedule should be invoked only on unscheduled, cancelled, or completed
// Jobs. To be safe, callers should always call Cancel before calling Schedule.
//
// Note, j will be modified.
func (j *Job) Schedule(d time.Duration) {
	// Create a new instance.
	earlyReturn := false

	// Capture the locker so that updating the timer does not cause a data race
	// when a timer fires and tries to obtain the lock (read the timer's locker).
	locker := j.locker
	j.instance = jobInstance{
		timer: j.clock.AfterFunc(d, func() {
			locker.Lock()
			defer locker.Unlock()

			if earlyReturn {
				// If we reach this point, it means that the timer fired while another
				// goroutine called Cancel while it had the lock. Simply return here
				// and do nothing further.
				earlyReturn = false
				return
			}

			j.fn()
		}),
		earlyReturn: &earlyReturn,
	}
}

// NewJob returns a new Job that can be used to schedule f to run in its own
// gorountine. l will be locked before calling f then unlocked after f returns.
//
//  var clock tcpip.StdClock
//  var mu sync.Mutex
//  message := "foo"
//  job := tcpip.NewJob(&clock, &mu, func() {
//    fmt.Println(message)
//  })
//  job.Schedule(time.Second)
//
//  mu.Lock()
//  message = "bar"
//  mu.Unlock()
//
//  // Output: bar
//
// f MUST NOT attempt to lock l.
//
// l MUST be locked prior to calling the returned job's Cancel().
//
//  var clock tcpip.StdClock
//  var mu sync.Mutex
//  message := "foo"
//  job := tcpip.NewJob(&clock, &mu, func() {
//    fmt.Println(message)
//  })
//  job.Schedule(time.Second)
//
//  mu.Lock()
//  job.Cancel()
//  mu.Unlock()
func NewJob(c Clock, l sync.Locker, f func()) *Job {
	return &Job{
		clock:  c,
		locker: l,
		fn:     f,
	}
}
