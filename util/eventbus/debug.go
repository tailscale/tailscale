// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"slices"
	"sync"
	"sync/atomic"
)

// A hook collects hook functions that can be run as a group.
type hook[T any] struct {
	sync.Mutex
	fns []hookFn[T]
}

var hookID atomic.Uint64

// add registers fn to be called when the hook is run. Returns an
// unregistration function that removes fn from the hook when called.
//
//lint:ignore U1000 Not used yet, but will be in an upcoming change
func (h *hook[T]) add(fn func(T)) (remove func()) {
	id := hookID.Add(1)
	h.Lock()
	defer h.Unlock()
	h.fns = append(h.fns, hookFn[T]{id, fn})
	return func() { h.remove(id) }
}

// remove removes the function with the given ID from the hook.
//
//lint:ignore U1000 Not used yet, but will be in an upcoming change
func (h *hook[T]) remove(id uint64) {
	h.Lock()
	defer h.Unlock()
	h.fns = slices.DeleteFunc(h.fns, func(f hookFn[T]) bool { return f.ID == id })
}

// active reports whether any functions are registered with the
// hook. This can be used to skip expensive work when the hook is
// inactive.
func (h *hook[T]) active() bool {
	h.Lock()
	defer h.Unlock()
	return len(h.fns) > 0
}

// run calls all registered functions with the value v.
func (h *hook[T]) run(v T) {
	h.Lock()
	defer h.Unlock()
	for _, fn := range h.fns {
		fn.Fn(v)
	}
}

type hookFn[T any] struct {
	ID uint64
	Fn func(T)
}
