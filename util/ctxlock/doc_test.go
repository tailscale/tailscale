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

func (r *Resource) GetFoo(ctx ctxlock.Context) string {
	defer ctxlock.Lock(ctx, &r.mu).Unlock() // Lock the mutex if not already held.
	return r.foo
}

func (r *Resource) SetFoo(ctx ctxlock.Context, foo string) {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	r.foo = foo
}

func (r *Resource) GetBar(ctx ctxlock.Context) string {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	return r.bar
}

func (r *Resource) SetBar(ctx ctxlock.Context, bar string) {
	defer ctxlock.Lock(ctx, &r.mu).Unlock()
	r.bar = bar
}

func (r *Resource) WithLock(ctx ctxlock.Context, f func(ctx ctxlock.Context)) {
	// Lock the mutex if not already held, and get a new context.
	ctx = ctxlock.Lock(ctx, &r.mu)
	defer ctx.Unlock()
	f(ctx) // Call the callback with the new context.
}

func ExampleContext() {
	var r Resource
	r.SetFoo(ctxlock.None(), "foo")
	r.SetBar(ctxlock.None(), "bar")
	r.WithLock(ctxlock.None(), func(ctx ctxlock.Context) {
		// This callback is invoked with r's lock held,
		// and ctx carries the lock state. This means we can safely call
		// other methods on r using ctx without causing a deadlock.
		r.SetFoo(ctx, r.GetFoo(ctx)+r.GetBar(ctx))
	})
	fmt.Println(r.GetFoo(ctxlock.None()))
	// Output: foobar
}

func ExampleContext_twoResources() {
	var r1, r2 Resource
	r1.SetFoo(ctxlock.None(), "foo")
	r2.SetBar(ctxlock.None(), "bar")
	r1.WithLock(ctxlock.None(), func(ctx ctxlock.Context) {
		// Here, r1's lock is held, but r2's lock is not.
		// So r2 will be locked when we call r2.GetBar(ctx).
		r1.SetFoo(ctx, r1.GetFoo(ctx)+r2.GetBar(ctx))
	})
	fmt.Println(r1.GetFoo(ctxlock.None()))
	// Output: foobar
}

func ExampleContext_zeroValue() {
	var r1, r2 Resource
	r1.SetFoo(ctxlock.Context{}, "foo")
	r2.SetBar(ctxlock.Context{}, "bar")
	r1.WithLock(ctxlock.Context{}, func(ctx ctxlock.Context) {
		// Here, r1's lock is held, but r2's lock is not.
		// So r2 will be locked when we call r2.GetBar(ctx).
		r1.SetFoo(ctx, r1.GetFoo(ctx)+r2.GetBar(ctx))
	})
	fmt.Println(r1.GetFoo(ctxlock.Context{}))
	// Output: foobar
}
