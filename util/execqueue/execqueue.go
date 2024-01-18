// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package execqueue implements an ordered asynchronous queue for executing functions.
package execqueue

import (
	"context"
	"errors"
	"sync"
)

type ExecQueue struct {
	mu         sync.Mutex
	closed     bool
	inFlight   bool          // whether a goroutine is running q.run
	doneWaiter chan struct{} // non-nil if waiter is waiting, then closed
	queue      []func()
}

func (q *ExecQueue) Add(f func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if q.inFlight {
		q.queue = append(q.queue, f)
	} else {
		q.inFlight = true
		go q.run(f)
	}
}

// RunSync waits for the queue to be drained and then synchronously runs f.
// It returns an error if the queue is closed before f is run or ctx expires.
func (q *ExecQueue) RunSync(ctx context.Context, f func()) error {
	for {
		if err := q.Wait(ctx); err != nil {
			return err
		}
		q.mu.Lock()
		if q.inFlight {
			q.mu.Unlock()
			continue
		}
		defer q.mu.Unlock()
		if q.closed {
			return errors.New("closed")
		}
		f()
		return nil
	}
}

func (q *ExecQueue) run(f func()) {
	f()

	q.mu.Lock()
	for len(q.queue) > 0 && !q.closed {
		f := q.queue[0]
		q.queue[0] = nil
		q.queue = q.queue[1:]
		q.mu.Unlock()
		f()
		q.mu.Lock()
	}
	q.inFlight = false
	q.queue = nil
	if q.doneWaiter != nil {
		close(q.doneWaiter)
		q.doneWaiter = nil
	}
	q.mu.Unlock()
}

// Shutdown asynchronously signals the queue to stop.
func (q *ExecQueue) Shutdown() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
}

// Wait waits for the queue to be empty.
func (q *ExecQueue) Wait(ctx context.Context) error {
	q.mu.Lock()
	waitCh := q.doneWaiter
	if q.inFlight && waitCh == nil {
		waitCh = make(chan struct{})
		q.doneWaiter = waitCh
	}
	q.mu.Unlock()

	if waitCh == nil {
		return nil
	}

	select {
	case <-waitCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
