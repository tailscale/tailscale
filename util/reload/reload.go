// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package reload contains functions that allow periodically reloading a value
// (e.g. a config file) from various sources.
package reload

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
)

// DefaultInterval is the default value for ReloadOpts.Interval if none is
// provided.
const DefaultInterval = 5 * time.Minute

// ReloadOpts specifies options for reloading a value. Various helper functions
// in this package can be used to create one of these specialized for a given
// use-case.
type ReloadOpts[T any] struct {
	// Read is called to obtain the data to be unmarshaled; e.g. by reading
	// from a file, or making a network request, etc.
	//
	// An error from this function is fatal when calling New, but only a
	// warning during reload.
	//
	// This value is required.
	Read func(context.Context) ([]byte, error)

	// Unmarshal is called with the data that the Read function returns and
	// should return a parsed form of the given value, or an error.
	//
	// An error from this function is fatal when calling New, but only a
	// warning during reload.
	//
	// This value is required.
	Unmarshal func([]byte) (T, error)

	// Logf is a logger used to print errors that occur on reload. If nil,
	// no messages are printed.
	Logf logger.Logf

	// Interval is the interval at which to reload the given data from the
	// source; if zero, DefaultInterval will be used.
	Interval time.Duration

	// IntervalJitter is the jitter to be added to the given Interval; if
	// provided, a duration between 0 and this value will be added to each
	// Interval when waiting.
	IntervalJitter time.Duration
}

func (r *ReloadOpts[T]) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *ReloadOpts[T]) intervalWithJitter() time.Duration {
	tt := r.Interval
	if tt == 0 {
		tt = DefaultInterval
	}
	if r.IntervalJitter == 0 {
		return tt
	}

	jitter := rand.N(r.IntervalJitter)
	return tt + jitter
}

// New creates and starts reloading the provided value as per opts. It returns
// a function that, when called, returns the current stored value, or an error
// that indicates something went wrong.
//
// The value will be present immediately upon return.
func New[T any](ctx context.Context, opts ReloadOpts[T]) (func() T, error) {
	// Create our reloader, which hasn't started.
	reloader, err := newUnstarted(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Start it
	go reloader.run()

	// Return the load function now that we're all set up.
	return reloader.store.Load, nil
}

type reloader[T any] struct {
	ctx   context.Context
	store syncs.AtomicValue[T]
	opts  ReloadOpts[T]
}

// newUnstarted creates a reloader that hasn't yet been started.
func newUnstarted[T any](ctx context.Context, opts ReloadOpts[T]) (*reloader[T], error) {
	if opts.Read == nil {
		return nil, fmt.Errorf("the Read function is required")
	}
	if opts.Unmarshal == nil {
		return nil, fmt.Errorf("the Unmarshal function is required")
	}

	// Start by reading and unmarshaling the value.
	data, err := opts.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading initial value: %w", err)
	}

	initial, err := opts.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling initial value: %v", err)
	}

	reloader := &reloader[T]{
		ctx:  ctx,
		opts: opts,
	}
	reloader.store.Store(initial)
	return reloader, nil
}

func (r *reloader[T]) run() {
	// Create a timer that we re-set each time we fire.
	timer := time.NewTimer(r.opts.intervalWithJitter())
	defer timer.Stop()

	for {
		select {
		case <-r.ctx.Done():
			r.opts.logf("run context is done")
			return
		case <-timer.C:
		}

		if err := r.updateOnce(); err != nil {
			r.opts.logf("error refreshing data: %v", err)
		}

		// Re-arm the timer after we're done; this is safe
		// since the only way this loop woke up was by reading
		// from timer.C
		timer.Reset(r.opts.intervalWithJitter())
	}
}

func (r *reloader[T]) updateOnce() error {
	data, err := r.opts.Read(r.ctx)
	if err != nil {
		return fmt.Errorf("reading data: %w", err)
	}
	next, err := r.opts.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("unmarshaling data: %w", err)
	}

	oldValue := r.store.Swap(next)
	if !reflect.DeepEqual(oldValue, next) {
		r.opts.logf("stored new value: %+v", next)
	}
	return nil
}

// FromJSONFile creates a ReloadOpts describing reloading a value of type T
// from the given JSON file on-disk.
func FromJSONFile[T any](path string) ReloadOpts[T] {
	return ReloadOpts[T]{
		Read: func(_ context.Context) ([]byte, error) {
			return os.ReadFile(path)
		},
		Unmarshal: func(b []byte) (T, error) {
			var ret, zero T
			if err := json.Unmarshal(b, &ret); err != nil {
				return zero, err
			}
			return ret, nil
		},
	}
}
