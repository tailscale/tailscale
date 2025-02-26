// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import "slices"

const maxQueuedItems = 16

// queue is an ordered queue of items.
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

// Add adds v to the end of the queue. Blocks until append can be
// done.
func (q *queue) Add(v any) {
	if !q.canAppend() {
		if q.start == 0 {
			panic("Add on a full queue")
		}

		// Slide remaining values back to the start of the array.
		n := copy(q.vals, q.vals[q.start:])
		clear(q.vals[len(q.vals)-n:])
		q.vals = q.vals[:n]
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

	clear(q.vals[q.start : q.start+1])
	q.start++
	if q.Empty() {
		// Reset cursor to start of array, it's free to do.
		q.start = 0
		q.vals = q.vals[:0]
	}
}

// Dump returns a copy of the queue's contents.
func (q *queue) Dump() []any {
	return slices.Clone(q.vals[q.start:])
}
