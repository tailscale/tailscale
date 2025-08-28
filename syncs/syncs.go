// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package syncs contains additional sync types and functionality.
package syncs

import (
	"context"
	"iter"
	"sync"
	"sync/atomic"

	"tailscale.com/util/mak"
)

// ClosedChan returns a channel that's already closed.
func ClosedChan() <-chan struct{} { return closedChan }

var closedChan = initClosedChan()

func initClosedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// AtomicValue is the generic version of [atomic.Value].
// See [MutexValue] for guidance on whether to use this type.
type AtomicValue[T any] struct {
	v atomic.Value
}

// wrappedValue is used to wrap a value T in a concrete type,
// otherwise atomic.Value.Store may panic due to mismatching types in interfaces.
// This wrapping is not necessary for non-interface kinds of T,
// but there is no harm in wrapping anyways.
// See https://cs.opensource.google/go/go/+/refs/tags/go1.22.2:src/sync/atomic/value.go;l=78
type wrappedValue[T any] struct{ v T }

// Load returns the value set by the most recent Store.
// It returns the zero value for T if the value is empty.
func (v *AtomicValue[T]) Load() T {
	x, _ := v.LoadOk()
	return x
}

// LoadOk is like Load but returns a boolean indicating whether the value was
// loaded.
func (v *AtomicValue[T]) LoadOk() (_ T, ok bool) {
	x := v.v.Load()
	if x != nil {
		return x.(wrappedValue[T]).v, true
	}
	var zero T
	return zero, false
}

// Store sets the value of the Value to x.
func (v *AtomicValue[T]) Store(x T) {
	v.v.Store(wrappedValue[T]{x})
}

// Swap stores new into Value and returns the previous value.
// It returns the zero value for T if the value is empty.
func (v *AtomicValue[T]) Swap(x T) (old T) {
	oldV := v.v.Swap(wrappedValue[T]{x})
	if oldV != nil {
		return oldV.(wrappedValue[T]).v
	}
	return old // zero value of T
}

// CompareAndSwap executes the compare-and-swap operation for the Value.
// It panics if T is not comparable.
func (v *AtomicValue[T]) CompareAndSwap(oldV, newV T) (swapped bool) {
	var zero T
	return v.v.CompareAndSwap(wrappedValue[T]{oldV}, wrappedValue[T]{newV}) ||
		// In the edge-case where [atomic.Value.Store] is uninitialized
		// and trying to compare with the zero value of T,
		// then compare-and-swap with the nil any value.
		(any(oldV) == any(zero) && v.v.CompareAndSwap(any(nil), wrappedValue[T]{newV}))
}

// MutexValue is a value protected by a mutex.
//
// AtomicValue, [MutexValue], [atomic.Pointer] are similar and
// overlap in their use cases.
//
//   - Use [atomic.Pointer] if the value being stored is a pointer and
//     you only ever need load and store operations.
//     An atomic pointer only occupies 1 word of memory.
//
//   - Use [MutexValue] if the value being stored is not a pointer or
//     you need the ability for a mutex to protect a set of operations
//     performed on the value.
//     A mutex-guarded value occupies 1 word of memory plus
//     the memory representation of T.
//
//   - AtomicValue is useful for non-pointer types that happen to
//     have the memory layout of a single pointer.
//     Examples include a map, channel, func, or a single field struct
//     that contains any prior types.
//     An atomic value occupies 2 words of memory.
//     Consequently, Storing of non-pointer types always allocates.
//
// Note that [AtomicValue] has the ability to report whether it was set
// while [MutexValue] lacks the ability to detect if the value was set
// and it happens to be the zero value of T. If such a use case is
// necessary, then you could consider wrapping T in [opt.Value].
type MutexValue[T any] struct {
	mu sync.Mutex
	v  T
}

// WithLock calls f with a pointer to the value while holding the lock.
// The provided pointer must not leak beyond the scope of the call.
func (m *MutexValue[T]) WithLock(f func(p *T)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.v)
}

// Load returns a shallow copy of the underlying value.
func (m *MutexValue[T]) Load() T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v
}

// Store stores a shallow copy of the provided value.
func (m *MutexValue[T]) Store(v T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v = v
}

// Swap stores new into m and returns the previous value.
func (m *MutexValue[T]) Swap(new T) (old T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, m.v = m.v, new
	return old
}

// WaitGroupChan is like a sync.WaitGroup, but has a chan that closes
// on completion that you can wait on. (This, you can only use the
// value once)
// Also, its zero value is not usable. Use the constructor.
type WaitGroupChan struct {
	n    int64         // atomic
	done chan struct{} // closed on transition to zero
}

// NewWaitGroupChan returns a new single-use WaitGroupChan.
func NewWaitGroupChan() *WaitGroupChan {
	return &WaitGroupChan{done: make(chan struct{})}
}

// DoneChan returns a channel that's closed on completion.
func (wg *WaitGroupChan) DoneChan() <-chan struct{} { return wg.done }

// Add adds delta, which may be negative, to the WaitGroupChan
// counter. If the counter becomes zero, all goroutines blocked on
// Wait or the Done chan are released. If the counter goes negative,
// Add panics.
//
// Note that calls with a positive delta that occur when the counter
// is zero must happen before a Wait. Calls with a negative delta, or
// calls with a positive delta that start when the counter is greater
// than zero, may happen at any time. Typically this means the calls
// to Add should execute before the statement creating the goroutine
// or other event to be waited for.
func (wg *WaitGroupChan) Add(delta int) {
	n := atomic.AddInt64(&wg.n, int64(delta))
	if n == 0 {
		close(wg.done)
	}
}

// Decr decrements the WaitGroup counter by one.
//
// (It is like sync.WaitGroup's Done method, but we don't use Done in
// this type, because it's ambiguous between Context.Done and
// WaitGroup.Done. So we use DoneChan and Decr instead.)
func (wg *WaitGroupChan) Decr() {
	wg.Add(-1)
}

// Wait blocks until the WaitGroupChan counter is zero.
func (wg *WaitGroupChan) Wait() { <-wg.done }

// Semaphore is a counting semaphore.
//
// Use NewSemaphore to create one.
type Semaphore struct {
	c chan struct{}
}

// NewSemaphore returns a semaphore with resource count n.
func NewSemaphore(n int) Semaphore {
	return Semaphore{c: make(chan struct{}, n)}
}

// Acquire blocks until a resource is acquired.
func (s Semaphore) Acquire() {
	s.c <- struct{}{}
}

// AcquireContext reports whether the resource was acquired before the ctx was done.
func (s Semaphore) AcquireContext(ctx context.Context) bool {
	select {
	case s.c <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// TryAcquire reports, without blocking, whether the resource was acquired.
func (s Semaphore) TryAcquire() bool {
	select {
	case s.c <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a resource.
func (s Semaphore) Release() {
	<-s.c
}

// Map is a Go map protected by a [sync.RWMutex].
// It is preferred over [sync.Map] for maps with entries that change
// at a relatively high frequency.
// This must not be shallow copied.
type Map[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
}

// Load loads the value for the provided key and whether it was found.
func (m *Map[K, V]) Load(key K) (value V, loaded bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, loaded = m.m[key]
	return value, loaded
}

// LoadFunc calls f with the value for the provided key
// regardless of whether the entry exists or not.
// The lock is held for the duration of the call to f.
func (m *Map[K, V]) LoadFunc(key K, f func(value V, loaded bool)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, loaded := m.m[key]
	f(value, loaded)
}

// Store stores the value for the provided key.
func (m *Map[K, V]) Store(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mak.Set(&m.m, key, value)
}

// LoadOrStore returns the value for the given key if it exists
// otherwise it stores value.
func (m *Map[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	if actual, loaded = m.Load(key); loaded {
		return actual, loaded
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	actual, loaded = m.m[key]
	if !loaded {
		actual = value
		mak.Set(&m.m, key, value)
	}
	return actual, loaded
}

// LoadOrInit returns the value for the given key if it exists
// otherwise f is called to construct the value to be set.
// The lock is held for the duration to prevent duplicate initialization.
func (m *Map[K, V]) LoadOrInit(key K, f func() V) (actual V, loaded bool) {
	if actual, loaded := m.Load(key); loaded {
		return actual, loaded
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if actual, loaded = m.m[key]; loaded {
		return actual, loaded
	}

	loaded = false
	actual = f()
	mak.Set(&m.m, key, actual)
	return actual, loaded
}

// LoadAndDelete returns the value for the given key if it exists.
// It ensures that the map is cleared of any entry for the key.
func (m *Map[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, loaded = m.m[key]
	if loaded {
		delete(m.m, key)
	}
	return value, loaded
}

// Delete deletes the entry identified by key.
func (m *Map[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, key)
}

// Keys iterates over all keys in the map in an undefined order.
// A read lock is held for the entire duration of the iteration.
// Use the [WithLock] method instead to mutate the map during iteration.
func (m *Map[K, V]) Keys() iter.Seq[K] {
	return func(yield func(K) bool) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for k := range m.m {
			if !yield(k) {
				return
			}
		}
	}
}

// Values iterates over all values in the map in an undefined order.
// A read lock is held for the entire duration of the iteration.
// Use the [WithLock] method instead to mutate the map during iteration.
func (m *Map[K, V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, v := range m.m {
			if !yield(v) {
				return
			}
		}
	}
}

// All iterates over all entries in the map in an undefined order.
// A read lock is held for the entire duration of the iteration.
// Use the [WithLock] method instead to mutate the map during iteration.
func (m *Map[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for k, v := range m.m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// WithLock calls f with the underlying map.
// Use of m2 must not escape the duration of this call.
// The write-lock is held for the entire duration of this call.
func (m *Map[K, V]) WithLock(f func(m2 map[K]V)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = make(map[K]V)
	}
	f(m.m)
}

// Len returns the length of the map.
func (m *Map[K, V]) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.m)
}

// Clear removes all entries from the map.
func (m *Map[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.m)
}

// Swap stores the value for the provided key, and returns the previous value
// (if any). If there was no previous value set, a zero value will be returned.
func (m *Map[K, V]) Swap(key K, value V) (oldValue V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldValue = m.m[key]
	mak.Set(&m.m, key, value)
	return oldValue
}
