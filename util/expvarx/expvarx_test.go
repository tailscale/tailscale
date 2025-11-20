// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package expvarx

import (
	"expvar"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func ExampleNewSafeFunc() {
	// An artificial blocker to emulate a slow operation.
	blocker := make(chan struct{})

	// limit is the amount of time a call can take before Value returns nil. No
	// new calls to the unsafe func will be started until the slow call
	// completes, at which point onSlow will be called.
	limit := time.Millisecond

	// onSlow is called with the final call duration and the final value in the
	// event a slow call.
	onSlow := func(d time.Duration, v any) {
		_ = d // d contains the time the call took
		_ = v // v contains the final value computed by the slow call
		fmt.Println("slow call!")
	}

	// An unsafe expvar.Func that blocks on the blocker channel.
	unsafeFunc := expvar.Func(func() any {
		for range blocker {
		}
		return "hello world"
	})

	// f implements the same interface as expvar.Func, but returns nil values
	// when the unsafe func is too slow.
	f := NewSafeFunc(unsafeFunc, limit, onSlow)

	fmt.Println(f.Value())
	fmt.Println(f.Value())
	close(blocker)
	time.Sleep(time.Millisecond)
	fmt.Println(f.Value())
	// Output: <nil>
	// <nil>
	// slow call!
	// hello world
}

func TestSafeFuncHappyPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count int
		f := NewSafeFunc(expvar.Func(func() any {
			count++
			return count
		}), time.Second, nil)

		if got, want := f.Value(), 1; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
		time.Sleep(5 * time.Second) // (fake time in synctest)
		if got, want := f.Value(), 2; got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestSafeFuncSlow(t *testing.T) {
	var count int
	blocker := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	f := NewSafeFunc(expvar.Func(func() any {
		defer wg.Done()
		count++
		<-blocker
		return count
	}), time.Millisecond, nil)

	if got := f.Value(); got != nil {
		t.Errorf("got %v; want nil", got)
	}
	if got := f.Value(); got != nil {
		t.Errorf("got %v; want nil", got)
	}

	close(blocker)
	wg.Wait()

	if count != 1 {
		t.Errorf("got count=%d; want 1", count)
	}
}

func TestSafeFuncSlowOnSlow(t *testing.T) {
	var count int
	blocker := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var slowDuration atomic.Pointer[time.Duration]
	var slowCallCount atomic.Int32
	var slowValue atomic.Value
	f := NewSafeFunc(expvar.Func(func() any {
		defer wg.Done()
		count++
		<-blocker
		return count
	}), time.Millisecond, func(d time.Duration, v any) {
		defer wg.Done()
		slowDuration.Store(&d)
		slowCallCount.Add(1)
		slowValue.Store(v)
	})

	for range 10 {
		if got := f.Value(); got != nil {
			t.Fatalf("got value=%v; want nil", got)
		}
	}

	close(blocker)
	wg.Wait()

	if count != 1 {
		t.Errorf("got count=%d; want 1", count)
	}
	if got, want := *slowDuration.Load(), 1*time.Millisecond; got < want {
		t.Errorf("got slowDuration=%v; want at least %d", got, want)
	}
	if got, want := slowCallCount.Load(), int32(1); got != want {
		t.Errorf("got slowCallCount=%d; want %d", got, want)
	}
	if got, want := slowValue.Load().(int), 1; got != want {
		t.Errorf("got slowValue=%d, want %d", got, want)
	}
}
