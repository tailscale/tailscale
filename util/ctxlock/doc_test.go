// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock_test

import (
	"fmt"
	"sync"

	"tailscale.com/syncs"
	"tailscale.com/util/ctxlock"
)

type Resource struct {
	mu       sync.Mutex
	foo, bar string
}

func (r *Resource) GetFoo(ctx ctxlock.Context[*sync.Mutex]) string {
	defer ctxlock.Lock(ctx, &r.mu).Unlock() // Lock the mutex if not already held.
	syncs.AssertLocked(&r.mu)               // Panics if mu is still unlocked.
	return r.foo
}

func (r *Resource) SetFoo(ctx ctxlock.Context[*sync.Mutex], foo string) {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	syncs.AssertLocked(&r.mu)
	r.foo = foo
}

func (r *Resource) GetBar(ctx ctxlock.Context[*sync.Mutex]) string {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	syncs.AssertLocked(&r.mu)
	return r.bar
}

func (r *Resource) SetBar(ctx ctxlock.Context[*sync.Mutex], bar string) {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	syncs.AssertLocked(&r.mu)
	r.bar = bar
}

func (r *Resource) WithLock(ctx ctxlock.Context[*sync.Mutex], f func(ctx ctxlock.Context[*sync.Mutex])) {
	// Lock the mutex if not already held, and get a new context.
	ctx = ctxlock.Lock(ctx, &r.mu)
	defer ctx.Unlock()
	syncs.AssertLocked(&r.mu)
	f(ctx) // Call the callback with the new context.
}

func ExampleContext() {
	var r Resource
	r.SetFoo(ctxlock.None[*sync.Mutex](), "foo")
	r.SetBar(ctxlock.None[*sync.Mutex](), "bar")
	r.WithLock(ctxlock.None[*sync.Mutex](), func(ctx ctxlock.Context[*sync.Mutex]) {
		// This callback is invoked with the Resource's lock held,
		// and the ctx tracks carries the lock state. This means we can safely call
		// other methods on the Resource using ctx without causing a deadlock.
		r.SetFoo(ctx, r.GetFoo(ctx)+r.GetBar(ctx))
	})
	fmt.Println(r.GetFoo(ctxlock.None[*sync.Mutex]()))
	// Output: foobar
}

func ExampleContext_twoResources() {
	var r1, r2 Resource
	r1.SetFoo(ctxlock.None[*sync.Mutex](), "foo")
	r2.SetBar(ctxlock.None[*sync.Mutex](), "bar")
	r1.WithLock(ctxlock.None[*sync.Mutex](), func(ctx ctxlock.Context[*sync.Mutex]) {
		// Here, r1's lock is held, but r2's lock is not.
		// So r2 will be locked when we call r2.SetBar(ctx).
		r1.SetFoo(ctx, r1.GetFoo(ctx)+r2.GetBar(ctx))
	})
	fmt.Println(r1.GetFoo(ctxlock.None[*sync.Mutex]()))
	// Output: foobar
}
