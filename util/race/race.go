// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package race contains a helper to "race" two functions, returning the first
// successful result. It also allows explicitly triggering the
// (possibly-waiting) second function when the first function returns an error
// or indicates that it should be retried.
package race

import (
	"context"
	"errors"
	"time"
)

type resultType int

const (
	first resultType = iota
	second
)

// queryResult is an internal type for storing the result of a function call
type queryResult[T any] struct {
	ty  resultType
	res T
	err error
}

// Func is the signature of a function to be called.
type Func[T any] func(context.Context) (T, error)

// Race allows running two functions concurrently and returning the first
// non-error result returned.
type Race[T any] struct {
	func1, func2  Func[T]
	d             time.Duration
	results       chan queryResult[T]
	startFallback chan struct{}
}

// New creates a new Race that, when Start is called, will immediately call
// func1 to obtain a result. After the timeout d or if triggered by an error
// response from func1, func2 will be called.
func New[T any](d time.Duration, func1, func2 Func[T]) *Race[T] {
	ret := &Race[T]{
		func1:         func1,
		func2:         func2,
		d:             d,
		results:       make(chan queryResult[T], 2),
		startFallback: make(chan struct{}),
	}
	return ret
}

// Start will start the "race" process, returning the first non-error result or
// the errors that occurred when calling func1 and/or func2.
func (rh *Race[T]) Start(ctx context.Context) (T, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// func1 is started immediately
	go func() {
		ret, err := rh.func1(ctx)
		rh.results <- queryResult[T]{first, ret, err}
	}()

	// func2 is started after a timeout
	go func() {
		wait := time.NewTimer(rh.d)
		defer wait.Stop()

		// Wait for our timeout, trigger, or context to finish.
		select {
		case <-ctx.Done():
			// Nothing to do; we're done
			var zero T
			rh.results <- queryResult[T]{second, zero, ctx.Err()}
			return
		case <-rh.startFallback:
		case <-wait.C:
		}

		ret, err := rh.func2(ctx)
		rh.results <- queryResult[T]{second, ret, err}
	}()

	// For each possible result, get it off the channel.
	var errs []error
	for range 2 {
		res := <-rh.results

		// If this was an error, store it and hope that the other
		// result gives us something.
		if res.err != nil {
			errs = append(errs, res.err)

			// Start the fallback function immediately if this is
			// the first function's error, to avoid having
			// to wait.
			if res.ty == first {
				close(rh.startFallback)
			}
			continue
		}

		// Got a valid response! Return it.
		return res.res, nil
	}

	// If we get here, both raced functions failed. Return whatever errors
	// we have, joined together.
	var zero T
	return zero, errors.Join(errs...)
}
