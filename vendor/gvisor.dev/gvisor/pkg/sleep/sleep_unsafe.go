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

// Package sleep allows goroutines to efficiently sleep on multiple sources of
// notifications (wakers). It offers O(1) complexity, which is different from
// multi-channel selects which have O(n) complexity (where n is the number of
// channels) and a considerable constant factor.
//
// It is similar to edge-triggered epoll waits, where the user registers each
// object of interest once, and then can repeatedly wait on all of them.
//
// A Waker object is used to wake a sleeping goroutine (G) up, or prevent it
// from going to sleep next. A Sleeper object is used to receive notifications
// from wakers, and if no notifications are available, to optionally sleep until
// one becomes available.
//
// A Waker can be associated with at most one Sleeper, but a Sleeper can be
// associated with multiple Wakers. A Sleeper has a list of asserted (ready)
// wakers; when Fetch() is called repeatedly, elements from this list are
// returned until the list becomes empty in which case the goroutine goes to
// sleep. When Assert() is called on a Waker, it adds itself to the Sleeper's
// asserted list and wakes the G up from its sleep if needed.
//
// Sleeper objects are expected to be used as follows, with just one goroutine
// executing this code:
//
//	// One time set-up.
//	s := sleep.Sleeper{}
//	s.AddWaker(&w1)
//	s.AddWaker(&w2)
//
//	// Called repeatedly.
//	for {
//		switch s.Fetch(true) {
//		case &w1:
//			// Do work triggered by w1 being asserted.
//		case &w2:
//			// Do work triggered by w2 being asserted.
//		}
//	}
//
// And Waker objects are expected to call w.Assert() when they want the sleeper
// to wake up and perform work.
//
// The notifications are edge-triggered, which means that if a Waker calls
// Assert() several times before the sleeper has the chance to wake up, it will
// only be notified once and should perform all pending work (alternatively, it
// can also call Assert() on the waker, to ensure that it will wake up again).
//
// The "unsafeness" here is in the casts to/from unsafe.Pointer, which is safe
// when only one type is used for each unsafe.Pointer (which is the case here),
// we should just make sure that this remains the case in the future. The usage
// of unsafe package could be confined to sharedWaker and sharedSleeper types
// that would hold pointers in atomic.Pointers, but the go compiler currently
// can't optimize these as well (it won't inline their method calls), which
// reduces performance.
package sleep

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// preparingG is stored in sleepers to indicate that they're preparing
	// to sleep.
	preparingG = 1
)

var (
	// assertedSleeper is a sentinel sleeper. A pointer to it is stored in
	// wakers that are asserted.
	assertedSleeper Sleeper
)

// Sleeper allows a goroutine to sleep and receive wake up notifications from
// Wakers in an efficient way.
//
// This is similar to edge-triggered epoll in that wakers are added to the
// sleeper once and the sleeper can then repeatedly sleep in O(1) time while
// waiting on all wakers.
//
// None of the methods in a Sleeper can be called concurrently. Wakers that have
// been added to a sleeper A can only be added to another sleeper after A.Done()
// returns. These restrictions allow this to be implemented lock-free.
//
// This struct is thread-compatible.
//
// +stateify savable
type Sleeper struct {
	_ sync.NoCopy

	// sharedList is a "stack" of asserted wakers. They atomically add
	// themselves to the front of this list as they become asserted.
	sharedList unsafe.Pointer `state:".(*Waker)"`

	// localList is a list of asserted wakers that is only accessible to the
	// waiter, and thus doesn't have to be accessed atomically. When
	// fetching more wakers, the waiter will first go through this list, and
	// only  when it's empty will it atomically fetch wakers from
	// sharedList.
	localList *Waker

	// allWakers is a list with all wakers that have been added to this
	// sleeper. It is used during cleanup to remove associations.
	allWakers *Waker

	// waitingG holds the G that is sleeping, if any. It is used by wakers
	// to determine which G, if any, they should wake.
	waitingG uintptr `state:"zero"`
}

// saveSharedList is invoked by stateify.
func (s *Sleeper) saveSharedList() *Waker {
	return (*Waker)(atomic.LoadPointer(&s.sharedList))
}

// loadSharedList is invoked by stateify.
func (s *Sleeper) loadSharedList(w *Waker) {
	atomic.StorePointer(&s.sharedList, unsafe.Pointer(w))
}

// AddWaker associates the given waker to the sleeper.
func (s *Sleeper) AddWaker(w *Waker) {
	if w.allWakersNext != nil {
		panic("waker has non-nil allWakersNext; owned by another sleeper?")
	}
	if w.next != nil {
		panic("waker has non-nil next; queued in another sleeper?")
	}

	// Add the waker to the list of all wakers.
	w.allWakersNext = s.allWakers
	s.allWakers = w

	// Try to associate the waker with the sleeper. If it's already
	// asserted, we simply enqueue it in the "ready" list.
	for {
		p := (*Sleeper)(atomic.LoadPointer(&w.s))
		if p == &assertedSleeper {
			s.enqueueAssertedWaker(w, true /* wakep */)
			return
		}

		if atomic.CompareAndSwapPointer(&w.s, usleeper(p), usleeper(s)) {
			return
		}
	}
}

// nextWaker returns the next waker in the notification list, blocking if
// needed. The parameter wakepOrSleep indicates that if the operation does not
// block, then we will need to explicitly wake a runtime P.
//
// Precondition: wakepOrSleep may be true iff block is true.
func (s *Sleeper) nextWaker(block, wakepOrSleep bool) *Waker {
	// Attempt to replenish the local list if it's currently empty.
	if s.localList == nil {
		for atomic.LoadPointer(&s.sharedList) == nil {
			// Fail request if caller requested that we
			// don't block.
			if !block {
				return nil
			}

			// Indicate to wakers that we're about to sleep,
			// this allows them to abort the wait by setting
			// waitingG back to zero (which we'll notice
			// before committing the sleep).
			atomic.StoreUintptr(&s.waitingG, preparingG)

			// Check if something was queued while we were
			// preparing to sleep. We need this interleaving
			// to avoid missing wake ups.
			if atomic.LoadPointer(&s.sharedList) != nil {
				atomic.StoreUintptr(&s.waitingG, 0)
				break
			}

			// Since we are sleeping for sure, we no longer
			// need to wakep once we get a value.
			wakepOrSleep = false

			// Try to commit the sleep and report it to the
			// tracer as a select.
			//
			// gopark puts the caller to sleep and calls
			// commitSleep to decide whether to immediately
			// wake the caller up or to leave it sleeping.
			const traceEvGoBlockSelect = 24
			// See:runtime2.go in the go runtime package for
			// the values to pass as the waitReason here.
			const waitReasonSelect = 9
			sync.Gopark(commitSleep, unsafe.Pointer(&s.waitingG), sync.WaitReasonSelect, sync.TraceEvGoBlockSelect, 0)
		}

		// Pull the shared list out and reverse it in the local
		// list. Given that wakers push themselves in reverse
		// order, we fix things here.
		v := (*Waker)(atomic.SwapPointer(&s.sharedList, nil))
		for v != nil {
			cur := v
			v = v.next

			cur.next = s.localList
			s.localList = cur
		}
	}

	// Remove the waker in the front of the list.
	w := s.localList
	s.localList = w.next

	// Do we need to wake a P?
	if wakepOrSleep {
		sync.Wakep()
	}

	return w
}

// commitSleep signals to wakers that the given g is now sleeping. Wakers can
// then fetch it and wake it.
//
// The commit may fail if wakers have been asserted after our last check, in
// which case they will have set s.waitingG to zero.
//
//go:norace
//go:nosplit
func commitSleep(g uintptr, waitingG unsafe.Pointer) bool {
	return sync.RaceUncheckedAtomicCompareAndSwapUintptr((*uintptr)(waitingG), preparingG, g)
}

// fetch is the backing implementation for Fetch and AssertAndFetch.
//
// Preconditions are the same as nextWaker.
//go:nosplit
func (s *Sleeper) fetch(block, wakepOrSleep bool) *Waker {
	for {
		w := s.nextWaker(block, wakepOrSleep)
		if w == nil {
			return nil
		}

		// Reassociate the waker with the sleeper. If the waker was
		// still asserted we can return it, otherwise try the next one.
		old := (*Sleeper)(atomic.SwapPointer(&w.s, usleeper(s)))
		if old == &assertedSleeper {
			return w
		}
	}
}

// Fetch fetches the next wake-up notification. If a notification is
// immediately available, the asserted waker is returned immediately.
// Otherwise, the behavior depends on the value of 'block': if true, the
// current goroutine blocks until a notification arrives and returns the
// asserted waker; if false, nil will be returned.
//
// N.B. This method is *not* thread-safe. Only one goroutine at a time is
//      allowed to call this method.
func (s *Sleeper) Fetch(block bool) *Waker {
	return s.fetch(block, false /* wakepOrSleep */)
}

// AssertAndFetch asserts the given waker and fetches the next wake-up notification.
// Note that this will always be blocking, since there is no value in joining a
// non-blocking operation.
//
// N.B. Like Fetch, this method is *not* thread-safe. This will also yield the current
//      P to the next goroutine, avoiding associated scheduled overhead.
//+checkescapes:all
//go:nosplit
func (s *Sleeper) AssertAndFetch(n *Waker) *Waker {
	n.assert(false /* wakep */)
	return s.fetch(true /* block */, true /* wakepOrSleep*/)
}

// Done is used to indicate that the caller won't use this Sleeper anymore. It
// removes the association with all wakers so that they can be safely reused
// by another sleeper after Done() returns.
func (s *Sleeper) Done() {
	// Remove all associations that we can, and build a list of the ones we
	// could not. An association can be removed right away from waker w if
	// w.s has a pointer to the sleeper, that is, the waker is not asserted
	// yet. By atomically switching w.s to nil, we guarantee that
	// subsequent calls to Assert() on the waker will not result in it
	// being queued.
	for w := s.allWakers; w != nil; w = s.allWakers {
		next := w.allWakersNext // Before zapping.
		if atomic.CompareAndSwapPointer(&w.s, usleeper(s), nil) {
			w.allWakersNext = nil
			w.next = nil
			s.allWakers = next // Move ahead.
			continue
		}

		// Dequeue exactly one waiter from the list, it may not be
		// this one but we know this one is in the process. We must
		// leave it in the asserted state but drop it from our lists.
		if w := s.nextWaker(true, false); w != nil {
			prev := &s.allWakers
			for *prev != w {
				prev = &((*prev).allWakersNext)
			}
			*prev = (*prev).allWakersNext
			w.allWakersNext = nil
			w.next = nil
		}
	}
}

// enqueueAssertedWaker enqueues an asserted waker to the "ready" circular list
// of wakers that want to notify the sleeper.
func (s *Sleeper) enqueueAssertedWaker(w *Waker, wakep bool) {
	// Add the new waker to the front of the list.
	for {
		v := (*Waker)(atomic.LoadPointer(&s.sharedList))
		w.next = v
		if atomic.CompareAndSwapPointer(&s.sharedList, uwaker(v), uwaker(w)) {
			break
		}
	}

	// Nothing to do if there isn't a G waiting.
	if atomic.LoadUintptr(&s.waitingG) == 0 {
		return
	}

	// Signal to the sleeper that a waker has been asserted.
	switch g := atomic.SwapUintptr(&s.waitingG, 0); g {
	case 0, preparingG:
	default:
		// We managed to get a G. Wake it up.
		sync.Goready(g, 0, wakep)
	}
}

// Waker represents a source of wake-up notifications to be sent to sleepers. A
// waker can be associated with at most one sleeper at a time, and at any given
// time is either in asserted or non-asserted state.
//
// Once asserted, the waker remains so until it is manually cleared or a sleeper
// consumes its assertion (i.e., a sleeper wakes up or is prevented from going
// to sleep due to the waker).
//
// This struct is thread-safe, that is, its methods can be called concurrently
// by multiple goroutines.
//
// Note, it is not safe to copy a Waker as its fields are modified by value
// (the pointer fields are individually modified with atomic operations).
//
// +stateify savable
type Waker struct {
	_ sync.NoCopy

	// s is the sleeper that this waker can wake up. Only one sleeper at a
	// time is allowed. This field can have three classes of values:
	// nil -- the waker is not asserted: it either is not associated with
	//     a sleeper, or is queued to a sleeper due to being previously
	//     asserted. This is the zero value.
	// &assertedSleeper -- the waker is asserted.
	// otherwise -- the waker is not asserted, and is associated with the
	//     given sleeper. Once it transitions to asserted state, the
	//     associated sleeper will be woken.
	s unsafe.Pointer `state:".(wakerState)"`

	// next is used to form a linked list of asserted wakers in a sleeper.
	next *Waker

	// allWakersNext is used to form a linked list of all wakers associated
	// to a given sleeper.
	allWakersNext *Waker
}

type wakerState struct {
	asserted bool
	other    *Sleeper
}

// saveS is invoked by stateify.
func (w *Waker) saveS() wakerState {
	s := (*Sleeper)(atomic.LoadPointer(&w.s))
	if s == &assertedSleeper {
		return wakerState{asserted: true}
	}
	return wakerState{other: s}
}

// loadS is invoked by stateify.
func (w *Waker) loadS(ws wakerState) {
	if ws.asserted {
		atomic.StorePointer(&w.s, unsafe.Pointer(&assertedSleeper))
	} else {
		atomic.StorePointer(&w.s, unsafe.Pointer(ws.other))
	}
}

// assert is the implementation for Assert.
//go:nosplit
func (w *Waker) assert(wakep bool) {
	// Nothing to do if the waker is already asserted. This check allows us
	// to complete this case (already asserted) without any interlocked
	// operations on x86.
	if atomic.LoadPointer(&w.s) == usleeper(&assertedSleeper) {
		return
	}

	// Mark the waker as asserted, and wake up a sleeper if there is one.
	switch s := (*Sleeper)(atomic.SwapPointer(&w.s, usleeper(&assertedSleeper))); s {
	case nil:
	case &assertedSleeper:
	default:
		s.enqueueAssertedWaker(w, wakep)
	}
}

// Assert moves the waker to an asserted state, if it isn't asserted yet. When
// asserted, the waker will cause its matching sleeper to wake up.
func (w *Waker) Assert() {
	w.assert(true /* wakep */)
}

// Clear moves the waker to then non-asserted state and returns whether it was
// asserted before being cleared.
//
// N.B. The waker isn't removed from the "ready" list of a sleeper (if it
// happens to be in one), but the sleeper will notice that it is not asserted
// anymore and won't return it to the caller.
func (w *Waker) Clear() bool {
	// Nothing to do if the waker is not asserted. This check allows us to
	// complete this case (already not asserted) without any interlocked
	// operations on x86.
	if atomic.LoadPointer(&w.s) != usleeper(&assertedSleeper) {
		return false
	}

	// Try to store nil in the sleeper, which indicates that the waker is
	// not asserted.
	return atomic.CompareAndSwapPointer(&w.s, usleeper(&assertedSleeper), nil)
}

// IsAsserted returns whether the waker is currently asserted (i.e., if it's
// currently in a state that would cause its matching sleeper to wake up).
func (w *Waker) IsAsserted() bool {
	return (*Sleeper)(atomic.LoadPointer(&w.s)) == &assertedSleeper
}

func usleeper(s *Sleeper) unsafe.Pointer {
	return unsafe.Pointer(s)
}

func uwaker(w *Waker) unsafe.Pointer {
	return unsafe.Pointer(w)
}
