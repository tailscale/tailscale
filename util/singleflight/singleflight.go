// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package singleflight provides a duplicate function call suppression
// mechanism.
//
// This is a Tailscale fork of Go's singleflight package which has had several
// homes in the past:
//
//   - https://github.com/golang/go/commit/61d3b2db6292581fc07a3767ec23ec94ad6100d1
//   - https://github.com/golang/groupcache/tree/master/singleflight
//   - https://pkg.go.dev/golang.org/x/sync/singleflight
//
// This fork adds generics.
package singleflight // import "tailscale.com/util/singleflight"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// errGoexit indicates the runtime.Goexit was called in
// the user given function.
var errGoexit = errors.New("runtime.Goexit was called")

// A panicError is an arbitrary value recovered from a panic
// with the stack trace during the execution of given function.
type panicError struct {
	value interface{}
	stack []byte
}

// Error implements error interface.
func (p *panicError) Error() string {
	return fmt.Sprintf("%v\n\n%s", p.value, p.stack)
}

func newPanicError(v interface{}) error {
	stack := debug.Stack()

	// The first line of the stack trace is of the form "goroutine N [status]:"
	// but by the time the panic reaches Do the goroutine may no longer exist
	// and its status will have changed. Trim out the misleading line.
	if line := bytes.IndexByte(stack[:], '\n'); line >= 0 {
		stack = stack[line+1:]
	}
	return &panicError{value: v, stack: stack}
}

// call is an in-flight or completed singleflight.Do call
type call[V any] struct {
	wg sync.WaitGroup

	// These fields are written once before the WaitGroup is done
	// and are only read after the WaitGroup is done.
	val V
	err error

	// These fields are read and written with the singleflight
	// mutex held before the WaitGroup is done, and are read but
	// not written after the WaitGroup is done.
	dups  int
	chans []chan<- Result[V]

	// These fields are only written when the call is being created, and
	// only in the DoChanContext method.
	cancel     context.CancelFunc
	ctxWaiters atomic.Int64
}

// Group represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type Group[K comparable, V any] struct {
	mu sync.Mutex     // protects m
	m  map[K]*call[V] // lazily initialized
}

// Result holds the results of Do, so they can be passed
// on a channel.
type Result[V any] struct {
	Val    V
	Err    error
	Shared bool
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *Group[K, V]) Do(key K, fn func() (V, error)) (v V, err error, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*call[V])
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.mu.Unlock()
		c.wg.Wait()

		if e, ok := c.err.(*panicError); ok {
			panic(e)
		} else if c.err == errGoexit {
			runtime.Goexit()
		}
		return c.val, c.err, true
	}
	c := new(call[V])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	g.doCall(c, key, fn)
	return c.val, c.err, c.dups > 0
}

// DoChan is like Do but returns a channel that will receive the
// results when they are ready.
//
// The returned channel will not be closed.
func (g *Group[K, V]) DoChan(key K, fn func() (V, error)) <-chan Result[V] {
	ch := make(chan Result[V], 1)
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*call[V])
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		c.chans = append(c.chans, ch)
		g.mu.Unlock()
		return ch
	}
	c := &call[V]{chans: []chan<- Result[V]{ch}}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	go g.doCall(c, key, fn)

	return ch
}

// DoChanContext is like [Group.DoChan], but supports context cancelation. The
// context passed to the fn function is a context that is canceled only when
// there are no callers waiting on a result (i.e. all callers have canceled
// their contexts).
//
// The context that is passed to the fn function is not derived from any of the
// input contexts, so context values will not be propagated. If context values
// are needed, they must be propagated explicitly.
//
// The returned channel will not be closed. The Result.Err field is set to the
// context error if the context is canceled.
func (g *Group[K, V]) DoChanContext(ctx context.Context, key K, fn func(context.Context) (V, error)) <-chan Result[V] {
	ch := make(chan Result[V], 1)
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*call[V])
	}
	c, ok := g.m[key]
	if ok {
		// Call already in progress; add to the waiters list and then
		// release the mutex.
		c.dups++
		c.ctxWaiters.Add(1)
		c.chans = append(c.chans, ch)
		g.mu.Unlock()
	} else {
		// The call hasn't been started yet; we need to start it.
		//
		// Create a context that is not canceled when the parent context is,
		// but otherwise propagates all values.
		callCtx, callCancel := context.WithCancel(context.Background())
		c = &call[V]{
			chans:  []chan<- Result[V]{ch},
			cancel: callCancel,
		}
		c.wg.Add(1)
		c.ctxWaiters.Add(1) // one caller waiting
		g.m[key] = c
		g.mu.Unlock()

		// Wrap our function to provide the context.
		go g.doCall(c, key, func() (V, error) {
			return fn(callCtx)
		})
	}

	// Instead of returning the channel directly, we need to track
	// when the call finishes so we can handle context cancelation.
	// Do so by creating an final channel that gets the
	// result and hooking that up to the wait function.
	final := make(chan Result[V], 1)
	go g.waitCtx(ctx, c, ch, final)
	return final
}

// waitCtx will wait on the provided call to finish, or the context to be done.
// If the context is done, and this is the last waiter, then the context
// provided to the underlying function will be canceled.
func (g *Group[K, V]) waitCtx(ctx context.Context, c *call[V], result <-chan Result[V], output chan<- Result[V]) {
	var res Result[V]
	select {
	case <-ctx.Done():
	case res = <-result:
	}

	// Decrement the caller count, and if we're the last one, cancel the
	// context we created. Do this in all cases, error and otherwise, so we
	// don't leak goroutines.
	//
	// Also wait on the call to finish, so we know that the call has
	// finished executing after the last caller has returned.
	if c.ctxWaiters.Add(-1) == 0 {
		c.cancel()
		c.wg.Wait()
	}

	// Ensure that context cancelation takes precedence over a value being
	// available by checking ctx.Err() before sending the result to the
	// caller. The select above will nondeterministically pick a case if a
	// result is available and the ctx.Done channel is closed, so we check
	// again here.
	if err := ctx.Err(); err != nil {
		res = Result[V]{Err: err}
	}
	output <- res
}

// doCall handles the single call for a key.
func (g *Group[K, V]) doCall(c *call[V], key K, fn func() (V, error)) {
	normalReturn := false
	recovered := false

	// use double-defer to distinguish panic from runtime.Goexit,
	// more details see https://golang.org/cl/134395
	defer func() {
		// the given function invoked runtime.Goexit
		if !normalReturn && !recovered {
			c.err = errGoexit
		}

		g.mu.Lock()
		defer g.mu.Unlock()
		c.wg.Done()
		if g.m[key] == c {
			delete(g.m, key)
		}

		if e, ok := c.err.(*panicError); ok {
			// In order to prevent the waiting channels from being blocked forever,
			// needs to ensure that this panic cannot be recovered.
			if len(c.chans) > 0 {
				go panic(e)
				select {} // Keep this goroutine around so that it will appear in the crash dump.
			} else {
				panic(e)
			}
		} else if c.err == errGoexit {
			// Already in the process of goexit, no need to call again
		} else {
			// Normal return
			for _, ch := range c.chans {
				ch <- Result[V]{c.val, c.err, c.dups > 0}
			}
		}
	}()

	func() {
		defer func() {
			if !normalReturn {
				// Ideally, we would wait to take a stack trace until we've determined
				// whether this is a panic or a runtime.Goexit.
				//
				// Unfortunately, the only way we can distinguish the two is to see
				// whether the recover stopped the goroutine from terminating, and by
				// the time we know that, the part of the stack trace relevant to the
				// panic has been discarded.
				if r := recover(); r != nil {
					c.err = newPanicError(r)
				}
			}
		}()

		c.val, c.err = fn()
		normalReturn = true
	}()

	if !normalReturn {
		recovered = true
	}
}

// Forget tells the singleflight to forget about a key.  Future calls
// to Do for this key will call the function rather than waiting for
// an earlier call to complete.
func (g *Group[K, V]) Forget(key K) {
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
}
