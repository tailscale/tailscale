// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package expvarx provides some extensions to the [expvar] package.
package expvarx

import (
	"encoding/json"
	"expvar"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/lazy"
)

// SafeFunc is a wrapper around [expvar.Func] that guards against unbounded call
// time and ensures that only a single call is in progress at any given time.
type SafeFunc struct {
	f      expvar.Func
	limit  time.Duration
	onSlow func(time.Duration, any)

	mu       syncs.Mutex
	inflight *lazy.SyncValue[any]
}

// NewSafeFunc returns a new SafeFunc that wraps f.
// If f takes longer than limit to execute then Value calls return nil.
// If onSlow is non-nil, it is called when f takes longer than limit to execute.
// onSlow is called with the duration of the slow call and the final computed
// value.
func NewSafeFunc(f expvar.Func, limit time.Duration, onSlow func(time.Duration, any)) *SafeFunc {
	return &SafeFunc{f: f, limit: limit, onSlow: onSlow}
}

// Value acts similarly to [expvar.Func.Value], but if the underlying function
// takes longer than the configured limit, all callers will receive nil until
// the underlying operation completes. On completion of the underlying
// operation, the onSlow callback is called if set.
func (s *SafeFunc) Value() any {
	s.mu.Lock()

	if s.inflight == nil {
		s.inflight = new(lazy.SyncValue[any])
	}
	var inflight = s.inflight
	s.mu.Unlock()

	// inflight ensures that only a single work routine is spawned at any given
	// time, but if the routine takes too long inflight is populated with a nil
	// result. The long running computed value is lost forever.
	return inflight.Get(func() any {
		start := time.Now()
		result := make(chan any, 1)

		// work is spawned in routine so that the caller can timeout.
		go func() {
			// Allow new work to be started after this work completes
			defer func() {
				s.mu.Lock()
				s.inflight = nil
				s.mu.Unlock()

			}()

			v := s.f.Value()
			result <- v
		}()

		select {
		case v := <-result:
			return v
		case <-time.After(s.limit):
			if s.onSlow != nil {
				go func() {
					s.onSlow(time.Since(start), <-result)
				}()
			}
			return nil
		}
	})
}

// String implements stringer in the same pattern as [expvar.Func], calling
// Value and serializing the result as JSON, ignoring errors.
func (s *SafeFunc) String() string {
	v, _ := json.Marshal(s.Value())
	return string(v)
}
