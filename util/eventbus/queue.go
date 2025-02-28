// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"slices"
)

const maxQueuedItems = 16

// queue is an ordered queue of length up to maxQueuedItems.
type queue struct {
	vals  []any
	start int
}

// canAppend reports whether a value can be appended to q.vals without
// shifting values around.
func (q *queue) canAppend() bool {
	return cap(q.vals) < maxQueuedItems || len(q.vals) < cap(q.vals)
}

func (q *queue) Full() bool {
	return q.start == 0 && !q.canAppend()
}

func (q *queue) Empty() bool {
	return q.start == len(q.vals)
}

func (q *queue) Len() int {
	return len(q.vals) - q.start
}

// Add adds v to the end of the queue. Blocks until append can be
// done.
func (q *queue) Add(v any) {
	if !q.canAppend() {
		if q.start == 0 {
			panic("Add on a full queue")
		}

		// Slide remaining values back to the start of the array.
		n := copy(q.vals, q.vals[q.start:])
		toClear := len(q.vals) - n
		clear(q.vals[len(q.vals)-toClear:])
		q.vals = q.vals[:n]
		q.start = 0
	}

	q.vals = append(q.vals, v)
}

// Peek returns the first value in the queue, without removing it from
// the queue, or nil if the queue is empty.
func (q *queue) Peek() any {
	if q.Empty() {
		return nil
	}

	return q.vals[q.start]
}

// Drop discards the first value in the queue, if any.
func (q *queue) Drop() {
	if q.Empty() {
		return
	}

	q.vals[q.start] = nil
	q.start++
	if q.Empty() {
		// Reset cursor to start of array, it's free to do.
		q.start = 0
		q.vals = q.vals[:0]
	}
}

// Snapshot returns a copy of the queue's contents.
func (q *queue) Snapshot() []any {
	return slices.Clone(q.vals[q.start:])
}
