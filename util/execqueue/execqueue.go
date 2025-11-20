// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package execqueue implements an ordered asynchronous queue for executing functions.
package execqueue

import (
	"context"
	"errors"

	"tailscale.com/syncs"
)

type ExecQueue struct {
	mu         syncs.Mutex
	ctx        context.Context    // context.Background + closed on Shutdown
	cancel     context.CancelFunc // closes ctx
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
	q.initCtxLocked()
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
	if q.cancel != nil {
		q.cancel()
	}
}

func (q *ExecQueue) initCtxLocked() {
	if q.ctx == nil {
		q.ctx, q.cancel = context.WithCancel(context.Background())
	}
}

// Wait waits for the queue to be empty or shut down.
func (q *ExecQueue) Wait(ctx context.Context) error {
	q.mu.Lock()
	q.initCtxLocked()
	waitCh := q.doneWaiter
	if q.inFlight && waitCh == nil {
		waitCh = make(chan struct{})
		q.doneWaiter = waitCh
	}
	closed := q.closed
	q.mu.Unlock()

	if closed {
		return errors.New("execqueue shut down")
	}
	if waitCh == nil {
		return nil
	}

	select {
	case <-waitCh:
		return nil
	case <-q.ctx.Done():
		return errors.New("execqueue shut down")
	case <-ctx.Done():
		return ctx.Err()
	}
}
