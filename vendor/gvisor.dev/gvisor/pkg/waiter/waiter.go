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

// Package waiter provides the implementation of a wait queue, where waiters can
// be enqueued to be notified when an event of interest happens.
//
// Becoming readable and/or writable are examples of events. Waiters are
// expected to use a pattern similar to this to make a blocking function out of
// a non-blocking one:
//
//	func (o *object) blockingRead(...) error {
//		err := o.nonBlockingRead(...)
//		if err != ErrAgain {
//			// Completed with no need to wait!
//			return err
//		}
//
//		e := createOrGetWaiterEntry(...)
//		o.EventRegister(&e, waiter.EventIn)
//		defer o.EventUnregister(&e)
//
//		// We need to try to read again after registration because the
//		// object may have become readable between the last attempt to
//		// read and read registration.
//		err = o.nonBlockingRead(...)
//		for err == ErrAgain {
//			wait()
//			err = o.nonBlockingRead(...)
//		}
//
//		return err
//	}
//
// Another goroutine needs to notify waiters when events happen. For example:
//
//	func (o *object) Write(...) ... {
//		// Do write work.
//		[...]
//
//		if oldDataAvailableSize == 0 && dataAvailableSize > 0 {
//			// If no data was available and now some data is
//			// available, the object became readable, so notify
//			// potential waiters about this.
//			o.Notify(waiter.EventIn)
//		}
//	}
package waiter

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// EventMask represents io events as used in the poll() syscall.
type EventMask uint64

// Events that waiters can wait on. The meaning is the same as those in the
// poll() syscall.
const (
	EventIn       EventMask = 0x01   // POLLIN
	EventPri      EventMask = 0x02   // POLLPRI
	EventOut      EventMask = 0x04   // POLLOUT
	EventErr      EventMask = 0x08   // POLLERR
	EventHUp      EventMask = 0x10   // POLLHUP
	EventRdNorm   EventMask = 0x0040 // POLLRDNORM
	EventWrNorm   EventMask = 0x0100 // POLLWRNORM
	EventInternal EventMask = 0x1000

	allEvents      EventMask = 0x1f | EventRdNorm | EventWrNorm
	ReadableEvents EventMask = EventIn | EventRdNorm
	WritableEvents EventMask = EventOut | EventWrNorm
)

// EventMaskFromLinux returns an EventMask representing the supported events
// from the Linux events e, which is in the format used by poll(2).
func EventMaskFromLinux(e uint32) EventMask {
	// Our flag definitions are currently identical to Linux.
	return EventMask(e) & allEvents
}

// ToLinux returns e in the format used by Linux poll(2).
func (e EventMask) ToLinux() uint32 {
	// Our flag definitions are currently identical to Linux.
	return uint32(e)
}

// Waitable contains the methods that need to be implemented by waitable
// objects.
type Waitable interface {
	// Readiness returns what the object is currently ready for. If it's
	// not ready for a desired purpose, the caller may use EventRegister and
	// EventUnregister to get notifications once the object becomes ready.
	//
	// Implementations should allow for events like EventHUp and EventErr
	// to be returned regardless of whether they are in the input EventMask.
	Readiness(mask EventMask) EventMask

	// EventRegister registers the given waiter entry to receive
	// notifications when an event occurs that makes the object ready for
	// at least one of the events in mask.
	EventRegister(e *Entry) error

	// EventUnregister unregisters a waiter entry previously registered with
	// EventRegister().
	EventUnregister(e *Entry)
}

// EventListener provides a notify callback.
type EventListener interface {
	// NotifyEvent is the function to be called when the waiter entry is
	// notified. It is responsible for doing whatever is needed to wake up
	// the waiter.
	//
	// The callback is supposed to perform minimal work, and cannot call
	// any method on the queue itself because it will be locked while the
	// callback is running.
	//
	// The mask indicates the events that occurred and that the entry is
	// interested in.
	NotifyEvent(mask EventMask)
}

// Entry represents a waiter that can be add to the a wait queue. It can
// only be in one queue at a time, and is added "intrusively" to the queue with
// no extra memory allocations.
//
// +stateify savable
type Entry struct {
	waiterEntry

	// eventListener receives the notification.
	eventListener EventListener

	// mask should be immutable once queued.
	mask EventMask
}

// Init initializes the Entry.
//
// This must only be called when unregistered.
func (e *Entry) Init(eventListener EventListener, mask EventMask) {
	e.eventListener = eventListener
	e.mask = mask
}

// Mask returns the entry mask.
func (e *Entry) Mask() EventMask {
	return e.mask
}

// NotifyEvent notifies the event listener.
//
// Mask should be the full set of active events.
func (e *Entry) NotifyEvent(mask EventMask) {
	if m := mask & e.mask; m != 0 {
		e.eventListener.NotifyEvent(m)
	}
}

// ChannelNotifier is a simple channel-based notification.
type ChannelNotifier chan struct{}

// NotifyEvent implements waiter.EventListener.NotifyEvent.
func (c ChannelNotifier) NotifyEvent(EventMask) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// NewChannelEntry initializes a new Entry that does a non-blocking write to a
// struct{} channel when the callback is called. It returns the new Entry
// instance and the channel being used.
func NewChannelEntry(mask EventMask) (e Entry, ch chan struct{}) {
	ch = make(chan struct{}, 1)
	e.Init(ChannelNotifier(ch), mask)
	return e, ch
}

type functionNotifier func(EventMask)

// NotifyEvent implements waiter.EventListener.NotifyEvent.
func (f functionNotifier) NotifyEvent(mask EventMask) {
	f(mask)
}

// NewFunctionEntry initializes a new Entry that calls the given function.
func NewFunctionEntry(mask EventMask, fn func(EventMask)) (e Entry) {
	e.Init(functionNotifier(fn), mask)
	return e
}

// Queue represents the wait queue where waiters can be added and
// notifiers can notify them when events happen.
//
// The zero value for waiter.Queue is an empty queue ready for use.
//
// +stateify savable
type Queue struct {
	list waiterList
	mu   sync.RWMutex `state:"nosave"`
}

// EventRegister adds a waiter to the wait queue.
func (q *Queue) EventRegister(e *Entry) {
	q.mu.Lock()
	q.list.PushBack(e)
	q.mu.Unlock()
}

// EventUnregister removes the given waiter entry from the wait queue.
func (q *Queue) EventUnregister(e *Entry) {
	q.mu.Lock()
	q.list.Remove(e)
	q.mu.Unlock()
}

// Notify notifies all waiters in the queue whose masks have at least one bit
// in common with the notification mask.
func (q *Queue) Notify(mask EventMask) {
	q.mu.RLock()
	for e := q.list.Front(); e != nil; e = e.Next() {
		m := mask & e.mask
		if m == 0 {
			continue
		}
		e.eventListener.NotifyEvent(m) // Skip intermediate call.
	}
	q.mu.RUnlock()
}

// Events returns the set of events being waited on. It is the union of the
// masks of all registered entries.
func (q *Queue) Events() EventMask {
	q.mu.RLock()
	defer q.mu.RUnlock()
	ret := EventMask(0)
	for e := q.list.Front(); e != nil; e = e.Next() {
		ret |= e.mask
	}
	return ret
}

// IsEmpty returns if the wait queue is empty or not.
func (q *Queue) IsEmpty() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.list.Front() == nil
}

// AlwaysReady implements the Waitable interface but is always ready. Embedding
// this struct into another struct makes it implement the boilerplate empty
// functions automatically.
type AlwaysReady struct {
}

// Readiness always returns the input mask because this object is always ready.
func (*AlwaysReady) Readiness(mask EventMask) EventMask {
	return mask
}

// EventRegister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*AlwaysReady) EventRegister(*Entry) error {
	return nil
}

// EventUnregister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*AlwaysReady) EventUnregister(e *Entry) {
}

// NeverReady implements the Waitable interface but is never ready. Otherwise,
// this is exactly the same as AlwaysReady.
type NeverReady struct {
}

// Readiness always returns the input mask because this object is always ready.
func (*NeverReady) Readiness(mask EventMask) EventMask {
	return mask
}

// EventRegister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*NeverReady) EventRegister(e *Entry) error {
	return nil
}

// EventUnregister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*NeverReady) EventUnregister(e *Entry) {
}
