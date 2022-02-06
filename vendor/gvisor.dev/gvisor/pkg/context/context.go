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

// Package context defines an internal context type.
//
// The given Context conforms to the standard Go context, but mandates
// additional methods that are specific to the kernel internals. Note however,
// that the Context described by this package carries additional constraints
// regarding concurrent access and retaining beyond the scope of a call.
//
// See the Context type for complete details.
package context

import (
	"context"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Blocker represents an object with control flow hooks.
//
// These may be used to perform blocking operations, sleep or otherwise
// wait, since there may be asynchronous events that require processing.
type Blocker interface {
	// Interrupt interrupts any Block operations.
	Interrupt()

	// Interrupted notes whether this context is Interrupted.
	Interrupted() bool

	// BlockOn blocks until one of the previously registered events occurs,
	// or some external interrupt (cancellation).
	//
	// The return value should indicate whether the wake-up occurred as a
	// result of the requested event (versus an external interrupt).
	BlockOn(waiter.Waitable, waiter.EventMask) bool

	// BlockWithTimeoutOn blocks until either the conditions of Block are
	// satisfied, or the timeout is hit. Note that deadlines are not supported
	// since the notion of "with respect to what clock" is not resolved.
	//
	// The return value is per BlockOn.
	BlockWithTimeoutOn(waiter.Waitable, waiter.EventMask, time.Duration) (time.Duration, bool)

	// UninterruptibleSleepStart indicates the beginning of an uninterruptible
	// sleep state (equivalent to Linux's TASK_UNINTERRUPTIBLE). If deactivate
	// is true and the Context represents a Task, the Task's AddressSpace is
	// deactivated.
	UninterruptibleSleepStart(deactivate bool)

	// UninterruptibleSleepFinish indicates the end of an uninterruptible sleep
	// state that was begun by a previous call to UninterruptibleSleepStart. If
	// activate is true and the Context represents a Task, the Task's
	// AddressSpace is activated. Normally activate is the same value as the
	// deactivate parameter passed to UninterruptibleSleepStart.
	UninterruptibleSleepFinish(activate bool)
}

// NoTask is an implementation of Blocker that does not block.
type NoTask struct {
	cancel chan struct{}
}

// Interrupt implements Blocker.Interrupt.
func (nt *NoTask) Interrupt() {
	select {
	case nt.cancel <- struct{}{}:
	default:
	}
}

// Interrupted implements Blocker.Interrupted.
func (nt *NoTask) Interrupted() bool {
	return nt.cancel != nil && len(nt.cancel) > 0
}

// BlockOn implements Blocker.BlockOn.
func (nt *NoTask) BlockOn(w waiter.Waitable, mask waiter.EventMask) bool {
	if nt.cancel == nil {
		nt.cancel = make(chan struct{}, 1)
	}
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	select {
	case <-nt.cancel:
		return false // Interrupted.
	case _, ok := <-ch:
		return ok
	}
}

// BlockWithTimeoutOn implements Blocker.BlockWithTimeoutOn.
func (nt *NoTask) BlockWithTimeoutOn(w waiter.Waitable, mask waiter.EventMask, duration time.Duration) (time.Duration, bool) {
	if nt.cancel == nil {
		nt.cancel = make(chan struct{}, 1)
	}
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	start := time.Now() // In system time.
	t := time.AfterFunc(duration, func() { ch <- struct{}{} })
	select {
	case <-nt.cancel:
		return time.Since(start), false // Interrupted.
	case _, ok := <-ch:
		if ok && t.Stop() {
			// Timer never fired.
			return time.Since(start), ok
		}
		// Timer fired, remain is zero.
		return time.Duration(0), ok
	}
}

// UninterruptibleSleepStart implmenents Blocker.UninterruptedSleepStart.
func (*NoTask) UninterruptibleSleepStart(bool) {}

// UninterruptibleSleepFinish implmenents Blocker.UninterruptibleSleepFinish.
func (*NoTask) UninterruptibleSleepFinish(bool) {}

// Context represents a thread of execution (hereafter "goroutine" to reflect
// Go idiosyncrasy). It carries state associated with the goroutine across API
// boundaries.
//
// While Context exists for essentially the same reasons as Go's standard
// context.Context, the standard type represents the state of an operation
// rather than that of a goroutine. This is a critical distinction:
//
// - Unlike context.Context, which "may be passed to functions running in
// different goroutines", it is *not safe* to use the same Context in multiple
// concurrent goroutines.
//
// - It is *not safe* to retain a Context passed to a function beyond the scope
// of that function call.
//
// In both cases, values extracted from the Context should be used instead.
type Context interface {
	context.Context
	log.Logger
	Blocker
}

// logContext implements basic logging.
type logContext struct {
	NoTask
	log.Logger
	context.Context
}

// bgContext is the context returned by context.Background.
var bgContext Context = &logContext{
	Context: context.Background(),
	Logger:  log.Log(),
}

// Background returns an empty context using the default logger.
// Generally, one should use the Task as their context when available, or avoid
// having to use a context in places where a Task is unavailable.
//
// Using a Background context for tests is fine, as long as no values are
// needed from the context in the tested code paths.
func Background() Context {
	return bgContext
}

// WithValue returns a copy of parent in which the value associated with key is
// val.
func WithValue(parent Context, key, val interface{}) Context {
	return &withValue{
		Context: parent,
		key:     key,
		val:     val,
	}
}

type withValue struct {
	Context
	key interface{}
	val interface{}
}

// Value implements Context.Value.
func (ctx *withValue) Value(key interface{}) interface{} {
	if key == ctx.key {
		return ctx.val
	}
	return ctx.Context.Value(key)
}
