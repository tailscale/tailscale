// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package latencyqueue provides a latency-bounded FIFO queue for asynchronous processing.
package latencyqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrClosed is returned by context.Cause() when Close() has been called.
	ErrClosed = errors.New("queue closed")

	// ErrAborted is returned by context.Cause() when Abort() has been called.
	ErrAborted = errors.New("queue processing aborted")

	// ErrLagged is returned by context.Cause() when the lag threshold was exceeded.
	ErrLagged = errors.New("queue lag threshold exceeded")
)

// ErrPanic wraps a panic value recovered from the processor function.
type ErrPanic struct {
	Panic any
}

func (e *ErrPanic) Error() string {
	return fmt.Sprintf("processor panic: %v", e.Panic)
}

// Queue is a latency-bounded FIFO queue for asynchronous processing.
//
// The queue is unbounded by item count or storage size, but bounded by the age
// of the oldest item. When an item exceeds the configured lag threshold,
// the queue's context is cancelled with ErrLagged.
//
// # Delivery Semantics
//
// During normal operation, each item is delivered exactly once to the processor,
// in the order enqueued. Items are processed one batch at a time, with each batch
// processed on a separate goroutine.
//
// On abnormal termination (lag threshold exceeded, processor panic, abort, or
// explicit close), unprocessed items are lost and any pending barriers are released.
type Queue[T any] struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu      sync.Mutex
	items   []queueItem[T]
	wakeup  chan struct{}
	started bool

	maxLag time.Duration

	numEnqueued  atomic.Uint64
	numProcessed atomic.Uint64

	done chan struct{}
}

type itemKind uint8

const (
	kindBatch itemKind = iota
	kindBarrier
)

type queueItem[T any] struct {
	kind     itemKind
	batch    []T
	enqueued time.Time
	barrier  chan struct{}
}

// QueueCounters contains observability metrics for the queue.
type QueueCounters struct {
	Enqueued  uint64
	Processed uint64
}

// New creates a bounded-latency queue that processes items asynchronously.
// The parent context is used for lifecycle management. If maxLag is > 0,
// items that remain in the queue longer than maxLag will cause the context
// to be cancelled with ErrLagged.
func New[T any](parent context.Context, maxLag time.Duration) *Queue[T] {
	ctx, cancel := context.WithCancelCause(parent)
	q := &Queue[T]{
		ctx:    ctx,
		cancel: cancel,
		items:  make([]queueItem[T], 0, 128),
		wakeup: make(chan struct{}, 1),
		maxLag: maxLag,
		done:   make(chan struct{}),
	}
	return q
}

// Start begins processing queued items with the given processor function.
// The processor receives a context (with lag deadline if applicable) and an item.
// The processor is considered infallible; errors should be handled within the processor.
// Must be called before Enqueue. Can only be called once.
func (q *Queue[T]) Start(processor func(context.Context, T)) {
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		panic("Start called multiple times")
	}
	q.started = true
	q.mu.Unlock()

	go q.run(processor)
}

// Close stops processing and releases resources.
// Unprocessed items are discarded and barriers are released.
// Blocks until processing stops.
func (q *Queue[T]) Close() {
	q.cancel(ErrClosed)
	<-q.done
}

// Abort stops processing immediately. Unprocessed items are discarded
// and barriers are released. The context will be cancelled with ErrAborted.
// Non-blocking.
func (q *Queue[T]) Abort() {
	q.cancel(ErrAborted)
}

// Enqueue adds a batch of items to the queue.
// Returns false if the queue has terminated (closed, lagged, or aborted).
func (q *Queue[T]) Enqueue(batch []T) bool {
	if len(batch) == 0 {
		return true
	}

	now := time.Now()
	item := queueItem[T]{
		kind:     kindBatch,
		batch:    batch,
		enqueued: now,
	}

	q.mu.Lock()

	select {
	case <-q.ctx.Done():
		return false
	default:
	}

	q.items = append(q.items, item)
	q.numEnqueued.Add(uint64(len(batch)))
	q.mu.Unlock()

	q.wake()
	return true
}

// Barrier returns a channel that closes when all previously enqueued items
// have been processed. Returns an immediately-closed channel if the queue
// has terminated.
func (q *Queue[T]) Barrier() <-chan struct{} {
	q.mu.Lock()

	ch := make(chan struct{})

	select {
	case <-q.ctx.Done():
		close(ch)
		return ch
	default:
	}

	item := queueItem[T]{
		kind:    kindBarrier,
		barrier: ch,
	}
	q.items = append(q.items, item)
	q.mu.Unlock()

	q.wake()
	return ch
}

// Done returns a channel that closes when processing stops.
func (q *Queue[T]) Done() <-chan struct{} {
	return q.done
}

// Context returns the queue's context, which is cancelled when the queue stops.
func (q *Queue[T]) Context() context.Context {
	return q.ctx
}

// Counters returns current queue metrics.
func (q *Queue[T]) Counters() QueueCounters {
	return QueueCounters{
		Enqueued:  q.numEnqueued.Load(),
		Processed: q.numProcessed.Load(),
	}
}

func (q *Queue[T]) wake() {
	select {
	case q.wakeup <- struct{}{}:
	default:
	}
}

func (q *Queue[T]) run(processor func(context.Context, T)) {
	defer close(q.done)
	defer q.drainAndReleaseBarriers()

	var (
		processingCh = make(chan error, 1)
		processing   chan error // nil when not processing, points to processingCh when processing
		itemCtx      context.Context
		itemCancel   context.CancelFunc
	)

	for {
		if processing == nil {
			q.mu.Lock()
			hasItems := len(q.items) > 0
			var item queueItem[T]
			if hasItems {
				item = q.items[0]
				q.items = q.items[1:]
			}
			q.mu.Unlock()

			if !hasItems {
				select {
				case <-q.ctx.Done():
					return
				case <-q.wakeup:
					continue
				}
			}

			if item.kind == kindBarrier {
				close(item.barrier)
				continue
			}

			itemCtx = q.ctx
			itemCancel = nil
			if q.maxLag > 0 {
				deadline := item.enqueued.Add(q.maxLag)
				remaining := time.Until(deadline)
				if remaining <= 0 {
					q.cancel(ErrLagged)
					return
				}
				var cancel context.CancelFunc
				itemCtx, cancel = context.WithDeadline(q.ctx, deadline)
				itemCancel = cancel
			}

			batch := item.batch
			processing = processingCh
			go func() {
				defer func() {
					if r := recover(); r != nil {
						processingCh <- &ErrPanic{Panic: r}
					} else {
						processingCh <- nil
					}
				}()
				for _, data := range batch {
					if itemCtx.Err() != nil {
						return
					}
					processor(itemCtx, data)
					q.numProcessed.Add(1)
				}
			}()
		}

		select {
		case <-q.ctx.Done():
			if itemCancel != nil {
				itemCancel()
			}
			if processing != nil {
				<-processing
			}
			return

		case err := <-processing:
			// Check lag BEFORE cancelling to distinguish deadline from manual cancel
			lagDetected := itemCtx.Err() == context.DeadlineExceeded

			if itemCancel != nil {
				itemCancel()
				itemCancel = nil
			}

			if err != nil {
				q.cancel(err)
				return
			}

			if lagDetected {
				q.cancel(ErrLagged)
				return
			}

			processing = nil

		case <-q.wakeup:
		}
	}
}

func (q *Queue[T]) drainAndReleaseBarriers() {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, item := range q.items {
		if item.kind == kindBarrier {
			close(item.barrier)
		}
	}
	q.items = nil
}
