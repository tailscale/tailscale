// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"tailscale.com/util/ctxlock"
)

type Resource struct {
	mu       sync.Mutex
	foo, bar string
}

func (r *Resource) GetFoo(ctx ctxlock.State) string {
	// Lock the mutex if not already held.
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	return r.foo
}

func (r *Resource) SetFoo(ctx ctxlock.State, foo string) {
	// You can do it this way, if you prefer
	// or if you need to pass the state to another function.
	ctx = ctxlock.Lock(ctx, &r.mu)
	defer ctx.Unlock()
	r.foo = foo
}

func (r *Resource) GetBar(ctx ctxlock.State) string {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	return r.bar
}

func (r *Resource) SetBar(ctx ctxlock.State, bar string) {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	r.bar = bar
}

func (r *Resource) WithLock(ctx ctxlock.State, f func(ctx ctxlock.State)) {
	// Lock the mutex if not already held, and get a new state.
	ctx = ctxlock.Lock(ctx, &r.mu)
	defer ctx.Unlock()
	f(ctx) // Call the callback with the new lock state.
}

func (r *Resource) HandleRequest(ctx context.Context, foo, bar string, f func(ls ctxlock.State) string) string {
	// Same, but with a standard [context.Context] instead of [ctxlock.State].
	// [ctxlock.Lock] is generic and works with both without allocating.
	// The ctx can be used for cancellation, etc.
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.foo = foo
	r.bar = bar
	return f(mu)
}

func (r *Resource) HandleIntRequest(ctx context.Context, foo, bar string, f func(ls ctxlock.State) int) int {
	// Same, but returns an int instead of a string,
	// and must not allocate with the unchecked implementation.
	mu := ctxlock.Lock(ctx, &r.mu)
	defer mu.Unlock()
	r.foo = foo
	r.bar = bar
	return f(mu)
}

func ExampleState() {
	var r Resource
	r.SetFoo(ctxlock.None(), "foo")
	r.SetBar(ctxlock.None(), "bar")
	r.WithLock(ctxlock.None(), func(ctx ctxlock.State) {
		// This callback is invoked with r's lock held,
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
		// Here, r1's lock is held, but r2's lock is not.
		// So r2 will be locked when we call r2.GetBar(ctx).
		r1.SetFoo(ctx, r1.GetFoo(ctx)+r2.GetBar(ctx))
	})
	fmt.Println(r1.GetFoo(ctxlock.None()))
	// Output: foobar
}

func ExampleState_stdContext() {
	var r Resource
	ctx := context.Background()
	result := r.HandleRequest(ctx, "foo", "bar", func(ctx ctxlock.State) string {
		// The r's lock is held, and ctx carries the lock state.
		return r.GetFoo(ctx) + r.GetBar(ctx)
	})
	fmt.Println(result)
	// Output: foobar
}

func TestAllocFree(t *testing.T) {
	if ctxlock.Checked {
		t.Skip("Exported implementation is not alloc-free (use --tags=ts_omit_ctxlock_checks)")
	}

	var r Resource
	ctx := context.Background()

	const runs = 1000
	if allocs := testing.AllocsPerRun(runs, func() {
		res := r.HandleIntRequest(ctx, "foo", "bar", func(ctx ctxlock.State) int {
			// The r's lock is held, and ctx carries the lock state.
			return len(r.GetFoo(ctx) + r.GetBar(ctx))
		})
		if res != 6 {
			t.Errorf("expected 6, got %d", res)
		}
	}); allocs != 0 {
		t.Errorf("expected 0 allocs, got %f", allocs)
	}
}
