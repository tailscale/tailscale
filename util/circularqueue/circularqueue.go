// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package circularqueue provides circular queues.
package circularqueue

import (
	"math"
	"sync"
)

const (
	// Head is the index of the head of a queue.
	Head = -1
)

// FIFO is a bounded queue that acts as if it has infinite depth. When an item
// is added to an already full queue, the oldest item in the queue is evicted
// to make room.
//
// Items in the queue are indexed, such that one can pop specific items by
// index. If an item is popped that is not at the head of the queue, all items
// up to the popped item are immediately evicted.
type FIFO[T any] struct {
	// mu protects all of the below fields
	mu sync.Mutex

	capacity int
	head     int
	tail     int
	onEvict  func(T)
	items    []T
}

// NewFIFO constructs a new [FIFO] queue with the given capacity and onEvict
// callback.
func NewFIFO[T any](capacity int, onEvict func(T)) *FIFO[T] {
	return &FIFO[T]{
		capacity: capacity,
		tail:     -1,
		onEvict:  onEvict,
		items:    make([]T, capacity),
	}
}

// Push pushes a new item onto the queue, evicting the item at the head if the
// queue is at capacity. If the number of items pushed to the queue reaches
// [math.MaxInt], this will panic with "FIFO queue sequence number exhausted".
func (q *FIFO[T]) Push(item T) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.tail++
	if q.tail == math.MaxInt {
		// We don't currently handle wrapping indexes
		panic("FIFO queue sequence number exhausted")
	}

	if q.tail-q.head >= q.capacity {
		q.onEvict(q.itemAtLocked(q.head))
		q.head++
	}
	q.items[q.tail%q.capacity] = item
}

// Pop removes the item at idx. If idx is past the tail or before the head of
// this queue, Pop returns nil. If an item at idx is available, all items in
// the queue at indices less than idx are immediately evicted. If idx <= [Head],
// this pops the item at the head of the queue.
func (q *FIFO[T]) Pop(idx int) *T {
	q.mu.Lock()
	defer q.mu.Unlock()

	if idx < 0 {
		idx = q.head
	} else if idx < q.head {
		return nil
	} else if idx > q.tail {
		return nil
	}

	// Evict items if necessary
	for i := q.head; i < idx; i++ {
		q.onEvict(q.itemAtLocked(i))
	}

	q.head = idx + 1
	item := q.itemAtLocked(idx)
	return &item
}

func (q *FIFO[T]) itemAtLocked(idx int) T {
	return q.items[idx%q.capacity]
}
