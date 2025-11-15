// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package goroutines

import (
	"sync/atomic"

	"tailscale.com/syncs"
	"tailscale.com/util/set"
)

// Tracker tracks a set of goroutines.
type Tracker struct {
	started atomic.Int64 // counter
	running atomic.Int64 // gauge

	mu     syncs.Mutex
	onDone set.HandleSet[func()]
}

func (t *Tracker) Go(f func()) {
	t.started.Add(1)
	t.running.Add(1)
	go t.goAndDecr(f)
}

func (t *Tracker) goAndDecr(f func()) {
	defer t.decr()
	f()
}

func (t *Tracker) decr() {
	t.running.Add(-1)

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, f := range t.onDone {
		go f()
	}
}

// AddDoneCallback adds a callback to be called in a new goroutine
// whenever a goroutine managed by t (excluding ones from this method)
// finishes. It returns a function to remove the callback.
func (t *Tracker) AddDoneCallback(f func()) (remove func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.onDone == nil {
		t.onDone = set.HandleSet[func()]{}
	}
	h := t.onDone.Add(f)
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(t.onDone, h)
	}
}

func (t *Tracker) RunningGoroutines() int64 {
	return t.running.Load()
}

func (t *Tracker) StartedGoroutines() int64 {
	return t.started.Load()
}
