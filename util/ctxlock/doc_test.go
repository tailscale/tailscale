// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"tailscale.com/util/ctxlock"
)

func ExampleMutex_reentrant() {
	var mu ctxlock.ReentrantMutex // shorthand for ctxlock.Mutex[ctxlock.Reentrant]

	// The mutex is reentrant, so foo can be called with or without holding the mu.
	// If mu is not already held, it will be locked on entry and unlocked on exit.
	// The [ctxlock.State] parameter carries the current lock state.
	foo := func(ctx ctxlock.State, msg string) {
		lock := ctxlock.Lock(ctx, &mu)
		defer lock.Unlock()
		fmt.Println(msg)
	}

	// Calling foo without holding the lock.
	foo(ctxlock.None(), "no lock")

	// Locking the mutex and calling foo again.
	lock := ctxlock.Lock(ctxlock.None(), &mu)
	foo(lock.State(), "with lock")
	defer lock.Unlock()

	// Output:
	// no lock
	// with lock
}

func ExampleMutex_nonReentrant() {
	var mu ctxlock.Mutex[ctxlock.NonReentrant]

	// The mutex is non-reentrant, so foo must only be called without holding the mu.
	// If mu is already held, it will panic attempting to lock it again.
	foo := func(ctx ctxlock.State, msg string) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("panic:", trimPanicMessage(r))
			}
		}()

		lock := ctxlock.Lock(ctx, &mu)
		defer lock.Unlock()
		fmt.Println(msg)
	}

	// Calling foo without holding the lock.
	foo(ctxlock.None(), "no lock")

	// Locking the mutex and calling foo again.
	// This will panic because the mutex is non-reentrant.
	lock := ctxlock.Lock(ctxlock.None(), &mu)
	foo(lock.State(), "with lock")
	defer lock.Unlock()

	// Output:
	// no lock
	// panic: non-reentrant mutex already locked
}

func ExampleRank() {
	var mu1 ctxlock.Mutex[rank1] // cannot be locked after mu2 or mu3
	var mu2 ctxlock.Mutex[rank2] // cannot be locked after mu3
	var mu3 ctxlock.Mutex[rank3]

	lock := ctxlock.Lock(ctxlock.None(), &mu1)
	defer lock.Unlock()
	fmt.Println("locked mu1")

	lock = ctxlock.Lock(lock.State(), &mu2)
	defer lock.Unlock()
	fmt.Println("locked mu2")

	lock = ctxlock.Lock(lock.State(), &mu3)
	defer lock.Unlock()
	fmt.Println("locked mu3")

	// Output:
	// locked mu1
	// locked mu2
	// locked mu3
}

func ExampleRank_lockOrderViolation() {
	var mu1 ctxlock.Mutex[rank1] // cannot be locked after mu2 or mu3
	var mu2 ctxlock.Mutex[rank2] // cannot be locked after mu3
	var mu3 ctxlock.Mutex[rank3]

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic:", trimPanicMessage(r))
		}
	}()

	// While we can lock mu2 first...
	lock := ctxlock.Lock(ctxlock.None(), &mu2)
	defer lock.Unlock()
	fmt.Println("locked mu2")

	// ...and then mu3...
	lock = ctxlock.Lock(lock.State(), &mu3)
	defer lock.Unlock()
	fmt.Println("locked mu3")

	// It is a lock order violation to lock mu1
	// after either mu2 or mu3.
	lock = ctxlock.Lock(lock.State(), &mu1)
	defer lock.Unlock()
	fmt.Println("locked mu1")

	// Output:
	// locked mu2
	// locked mu3
	// panic: cannot lock ctxlock_test.rank1 after ctxlock_test.rank3
}

func ExampleState_resource() {
	var r Resource
	r.SetFoo(ctxlock.None(), "foo")
	r.SetBar(ctxlock.None(), "bar")
	r.WithLock(ctxlock.None(), func(ctx ctxlock.State) {
		// This callback is invoked with r's mutex held,
		// and ctx carries the lock state. This means we can safely call
		// other methods on r using ctx without causing a deadlock.
		r.SetFoo(ctx, r.GetFoo(ctx)+r.GetBar(ctx))
	})
	fmt.Println(r.GetFoo(ctxlock.None()))
	// Output: foobar
}

func ExampleState_twoResources() {
	var r1, r2 Resource
	r1.SetFoo(ctxlock.None(), "foo")
	r2.SetBar(ctxlock.None(), "bar")
	r1.WithLock(ctxlock.None(), func(ctx ctxlock.State) {
		// Here, r1's mutex is held, but r2's mutex is not.
		// So r2 will be locked when we call r2.GetBar(ctx).
		r1.SetFoo(ctx, r1.GetFoo(ctx)+r2.GetBar(ctx))
	})
	fmt.Println(r1.GetFoo(ctxlock.None()))
	// Output: foobar
}

func ExampleState_withStdContext() {
	var r Resource
	ctx := context.Background()
	result := r.HandleRequest(ctx, "foo", "bar", func(ctx ctxlock.State) string {
		// The r's mutex is held, and ctx carries the lock state.
		return r.GetFoo(ctx) + r.GetBar(ctx)
	})
	fmt.Println(result)
	// Output: foobar
}

func TestEndToEndAllocFree(t *testing.T) {
	if ctxlock.IsChecked {
		t.Skip("Exported implementation is not alloc-free (use --tags=ts_omit_ctxlock_checks).")
	}

	var r Resource
	const N = 1000
	if allocs := testing.AllocsPerRun(N, func() {
		res := r.HandleIntRequest(context.Background(), "foo", "bar", func(ctx ctxlock.State) int {
			// The r's mutex is held, and ctx carries the lock state.
			return len(r.GetFoo(ctx) + r.GetBar(ctx))
		})
		if res != 6 {
			t.Errorf("expected 6, got %d", res)
		}
	}); allocs != 0 {
		t.Errorf("expected 0 allocs, got %f", allocs)
	}
}

type (
	rank1 struct{}
	rank2 struct{}
	rank3 struct{}
)

// CheckLockAfter implements [ctxlock.Rank].
func (r rank1) CheckLockAfter(r2 ctxlock.Rank) error {
	switch r2.(type) {
	case rank2, rank3:
		return fmt.Errorf("cannot lock %T after %T", r, r2)
	default:
		return nil
	}
}

// CheckLockAfter implements [ctxlock.Rank].
func (r rank2) CheckLockAfter(r2 ctxlock.Rank) error {
	switch r2.(type) {
	case rank2, rank3:
		return fmt.Errorf("cannot lock %T after %T", r, r2)
	default:
		return nil
	}
}

// CheckLockAfter implements [ctxlock.Rank].
func (a rank3) CheckLockAfter(b ctxlock.Rank) error {
	return nil
}

type Resource struct {
	mu       ctxlock.ReentrantMutex
	foo, bar string
}

func (r *Resource) GetFoo(ctx ctxlock.State) string {
	// Lock the mutex if not already held,
	// and unlock it when the function returns.
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	return r.foo
}

func (r *Resource) SetFoo(ctx ctxlock.State, foo string) {
	// You can do it this way, if you prefer.
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.foo = foo
}

func (r *Resource) GetBar(ctx ctxlock.State) string {
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	return r.bar
}

func (r *Resource) SetBar(ctx ctxlock.State, bar string) {
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.bar = bar
}

func (r *Resource) WithLock(ctx ctxlock.State, f func(ctx ctxlock.State)) {
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	// Call the callback with the new lock state.
	f(mu.State())
}

func (r *Resource) HandleRequest(ctx context.Context, foo, bar string, f func(ls ctxlock.State) string) string {
	// Same, but with a standard [context.Context] instead of [ctxlock.State].
	// [ctxlock.Lock] is generic and works with both without allocating.
	// The ctx can be used for cancellation, etc.
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.foo = foo
	r.bar = bar
	return f(mu.State())
}

func (r *Resource) HandleIntRequest(ctx context.Context, foo, bar string, f func(ls ctxlock.State) int) int {
	// Same, but returns an int instead of a string.
	// It must not allocate with the checked implementation.
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.foo = foo
	r.bar = bar
	return f(mu.State())
}

func trimPanicMessage(r any) string {
	msg := fmt.Sprintf("%v", r)
	msg = strings.TrimSpace(msg)
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		return msg[:i]
	}
	return msg
}
