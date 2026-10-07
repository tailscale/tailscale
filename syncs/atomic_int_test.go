// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syncs_test

import (
	"fmt"
	"sync"
	"testing"

	"tailscale.com/syncs"
)

// userID is a named int64 type with methods, used to verify that values
// returned by the atomic wrappers retain their methods.
type userID int64

func (u userID) IsZero() bool   { return u == 0 }
func (u userID) String() string { return fmt.Sprintf("user:%d", int64(u)) }

func TestAtomicInt64(t *testing.T) {
	var x syncs.AtomicInt64[userID]

	if got := x.Load(); got != 0 {
		t.Errorf("zero value Load = %v, want 0", got)
	}
	if got := x.Load(); !got.IsZero() {
		t.Errorf("IsZero on returned value = false, want true")
	}

	x.Store(userID(42))
	if got, want := x.Load(), userID(42); got != want {
		t.Errorf("Load after Store = %v, want %v", got, want)
	}
	if got, want := x.Load().String(), "user:42"; got != want {
		t.Errorf("String on returned value = %q, want %q", got, want)
	}

	if got, want := x.Add(userID(1)), userID(43); got != want {
		t.Errorf("Add = %v, want %v", got, want)
	}
	if got, want := x.Swap(userID(7)), userID(43); got != want {
		t.Errorf("Swap old = %v, want %v", got, want)
	}
	if got, want := x.Load(), userID(7); got != want {
		t.Errorf("Load after Swap = %v, want %v", got, want)
	}

	if swapped := x.CompareAndSwap(userID(7), userID(100)); !swapped {
		t.Errorf("CompareAndSwap matching returned false")
	}
	if swapped := x.CompareAndSwap(userID(7), userID(200)); swapped {
		t.Errorf("CompareAndSwap non-matching returned true")
	}
	if got, want := x.Load(), userID(100); got != want {
		t.Errorf("Load after CompareAndSwap = %v, want %v", got, want)
	}

	x.Store(userID(0b1100))
	if got, want := x.And(userID(0b1010)), userID(0b1100); got != want {
		t.Errorf("And old = %#b, want %#b", got, want)
	}
	if got, want := x.Load(), userID(0b1000); got != want {
		t.Errorf("Load after And = %#b, want %#b", got, want)
	}
	if got, want := x.Or(userID(0b0001)), userID(0b1000); got != want {
		t.Errorf("Or old = %#b, want %#b", got, want)
	}
	if got, want := x.Load(), userID(0b1001); got != want {
		t.Errorf("Load after Or = %#b, want %#b", got, want)
	}
}

func TestAtomicInt32(t *testing.T) {
	type counter int32
	var x syncs.AtomicInt32[counter]

	x.Store(counter(5))
	if got, want := x.Add(counter(3)), counter(8); got != want {
		t.Errorf("Add = %v, want %v", got, want)
	}
	if got, want := x.Swap(counter(1)), counter(8); got != want {
		t.Errorf("Swap old = %v, want %v", got, want)
	}
	if !x.CompareAndSwap(counter(1), counter(2)) {
		t.Errorf("CompareAndSwap matching returned false")
	}
	if got, want := x.Load(), counter(2); got != want {
		t.Errorf("Load = %v, want %v", got, want)
	}
}

func TestAtomicUint32(t *testing.T) {
	type streamID uint32
	var x syncs.AtomicUint32[streamID]

	x.Store(streamID(0x1000))
	if got, want := x.Or(streamID(0x0001)), streamID(0x1000); got != want {
		t.Errorf("Or old = %#x, want %#x", got, want)
	}
	if got, want := x.Load(), streamID(0x1001); got != want {
		t.Errorf("Load after Or = %#x, want %#x", got, want)
	}
	if got, want := x.And(streamID(0xF000)), streamID(0x1001); got != want {
		t.Errorf("And old = %#x, want %#x", got, want)
	}
	if got, want := x.Load(), streamID(0x1000); got != want {
		t.Errorf("Load after And = %#x, want %#x", got, want)
	}
}

func TestAtomicUint64(t *testing.T) {
	type bytes uint64
	var x syncs.AtomicUint64[bytes]

	if got, want := x.Add(bytes(10)), bytes(10); got != want {
		t.Errorf("Add = %v, want %v", got, want)
	}
	if got, want := x.Swap(bytes(3)), bytes(10); got != want {
		t.Errorf("Swap old = %v, want %v", got, want)
	}
	if !x.CompareAndSwap(bytes(3), bytes(99)) {
		t.Errorf("CompareAndSwap matching returned false")
	}
	if got, want := x.Load(), bytes(99); got != want {
		t.Errorf("Load = %v, want %v", got, want)
	}
}

func TestAtomicInt64Concurrent(t *testing.T) {
	var x syncs.AtomicInt64[userID]
	const workers, increments = 100, 1000

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for range increments {
				x.Add(1)
			}
		}()
	}
	wg.Wait()

	if got, want := x.Load(), userID(workers*increments); got != want {
		t.Errorf("Load = %v, want %v", got, want)
	}
}
