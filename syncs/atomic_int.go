// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import "sync/atomic"

// AtomicInt32 is the generic version of [atomic.Int32].
// It allows T to be a named type (such as a type with methods) whose
// underlying type is int32.
// The zero value is zero. It must not be copied after first use.
type AtomicInt32[T ~int32] struct {
	v atomic.Int32
}

// Load returns the value stored in x.
func (x *AtomicInt32[T]) Load() T { return T(x.v.Load()) }

// Store sets the value stored in x to val.
func (x *AtomicInt32[T]) Store(val T) { x.v.Store(int32(val)) }

// Swap stores new into x and returns the previous value.
func (x *AtomicInt32[T]) Swap(new T) (old T) { return T(x.v.Swap(int32(new))) }

// CompareAndSwap executes the compare-and-swap operation for x.
func (x *AtomicInt32[T]) CompareAndSwap(old, new T) (swapped bool) {
	return x.v.CompareAndSwap(int32(old), int32(new))
}

// Add atomically adds delta to x and returns the new value.
func (x *AtomicInt32[T]) Add(delta T) (new T) { return T(x.v.Add(int32(delta))) }

// And atomically performs a bitwise AND of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicInt32[T]) And(mask T) (old T) { return T(x.v.And(int32(mask))) }

// Or atomically performs a bitwise OR of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicInt32[T]) Or(mask T) (old T) { return T(x.v.Or(int32(mask))) }

// AtomicInt64 is the generic version of [atomic.Int64].
// It allows T to be a named type (such as a type with methods) whose
// underlying type is int64.
// The zero value is zero. It must not be copied after first use.
type AtomicInt64[T ~int64] struct {
	v atomic.Int64
}

// Load returns the value stored in x.
func (x *AtomicInt64[T]) Load() T { return T(x.v.Load()) }

// Store sets the value stored in x to val.
func (x *AtomicInt64[T]) Store(val T) { x.v.Store(int64(val)) }

// Swap stores new into x and returns the previous value.
func (x *AtomicInt64[T]) Swap(new T) (old T) { return T(x.v.Swap(int64(new))) }

// CompareAndSwap executes the compare-and-swap operation for x.
func (x *AtomicInt64[T]) CompareAndSwap(old, new T) (swapped bool) {
	return x.v.CompareAndSwap(int64(old), int64(new))
}

// Add atomically adds delta to x and returns the new value.
func (x *AtomicInt64[T]) Add(delta T) (new T) { return T(x.v.Add(int64(delta))) }

// And atomically performs a bitwise AND of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicInt64[T]) And(mask T) (old T) { return T(x.v.And(int64(mask))) }

// Or atomically performs a bitwise OR of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicInt64[T]) Or(mask T) (old T) { return T(x.v.Or(int64(mask))) }

// AtomicUint32 is the generic version of [atomic.Uint32].
// It allows T to be a named type (such as a type with methods) whose
// underlying type is uint32.
// The zero value is zero. It must not be copied after first use.
type AtomicUint32[T ~uint32] struct {
	v atomic.Uint32
}

// Load returns the value stored in x.
func (x *AtomicUint32[T]) Load() T { return T(x.v.Load()) }

// Store sets the value stored in x to val.
func (x *AtomicUint32[T]) Store(val T) { x.v.Store(uint32(val)) }

// Swap stores new into x and returns the previous value.
func (x *AtomicUint32[T]) Swap(new T) (old T) { return T(x.v.Swap(uint32(new))) }

// CompareAndSwap executes the compare-and-swap operation for x.
func (x *AtomicUint32[T]) CompareAndSwap(old, new T) (swapped bool) {
	return x.v.CompareAndSwap(uint32(old), uint32(new))
}

// Add atomically adds delta to x and returns the new value.
func (x *AtomicUint32[T]) Add(delta T) (new T) { return T(x.v.Add(uint32(delta))) }

// And atomically performs a bitwise AND of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicUint32[T]) And(mask T) (old T) { return T(x.v.And(uint32(mask))) }

// Or atomically performs a bitwise OR of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicUint32[T]) Or(mask T) (old T) { return T(x.v.Or(uint32(mask))) }

// AtomicUint64 is the generic version of [atomic.Uint64].
// It allows T to be a named type (such as a type with methods) whose
// underlying type is uint64.
// The zero value is zero. It must not be copied after first use.
type AtomicUint64[T ~uint64] struct {
	v atomic.Uint64
}

// Load returns the value stored in x.
func (x *AtomicUint64[T]) Load() T { return T(x.v.Load()) }

// Store sets the value stored in x to val.
func (x *AtomicUint64[T]) Store(val T) { x.v.Store(uint64(val)) }

// Swap stores new into x and returns the previous value.
func (x *AtomicUint64[T]) Swap(new T) (old T) { return T(x.v.Swap(uint64(new))) }

// CompareAndSwap executes the compare-and-swap operation for x.
func (x *AtomicUint64[T]) CompareAndSwap(old, new T) (swapped bool) {
	return x.v.CompareAndSwap(uint64(old), uint64(new))
}

// Add atomically adds delta to x and returns the new value.
func (x *AtomicUint64[T]) Add(delta T) (new T) { return T(x.v.Add(uint64(delta))) }

// And atomically performs a bitwise AND of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicUint64[T]) And(mask T) (old T) { return T(x.v.And(uint64(mask))) }

// Or atomically performs a bitwise OR of x and mask, storing the result
// in x, and returns the previous value.
func (x *AtomicUint64[T]) Or(mask T) (old T) { return T(x.v.Or(uint64(mask))) }
