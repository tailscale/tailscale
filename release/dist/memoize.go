// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dist

import (
	"sync"

	"tailscale.com/util/deephash"
)

// MemoizedFn is a function that memoize.Do can call.
type MemoizedFn[T any] func() (T, error)

// Memoize runs MemoizedFns and remembers their results.
type Memoize[O any] struct {
	mu       sync.Mutex
	cond     *sync.Cond
	outs     map[deephash.Sum]O
	errs     map[deephash.Sum]error
	inflight map[deephash.Sum]bool
}

// Do runs fn and returns its result.
// fn is only run once per unique key. Subsequent Do calls with the same key
// return the memoized result of the first call, even if fn is a different
// function.
func (m *Memoize[O]) Do(key any, fn MemoizedFn[O]) (ret O, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cond == nil {
		m.cond = sync.NewCond(&m.mu)
		m.outs = map[deephash.Sum]O{}
		m.errs = map[deephash.Sum]error{}
		m.inflight = map[deephash.Sum]bool{}
	}

	k := deephash.Hash(&key)

	for m.inflight[k] {
		m.cond.Wait()
	}
	if err := m.errs[k]; err != nil {
		var ret O
		return ret, err
	}
	if ret, ok := m.outs[k]; ok {
		return ret, nil
	}

	m.inflight[k] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.inflight, k)
		if err != nil {
			m.errs[k] = err
		} else {
			m.outs[k] = ret
		}
		m.cond.Broadcast()
	}()

	ret, err = fn()
	if err != nil {
		var ret O
		return ret, err
	}
	return ret, nil
}

// once is like memoize, but for functions that don't return non-error values.
type once struct {
	m Memoize[any]
}

// Do runs fn.
// fn is only run once per unique key. Subsequent Do calls with the same key
// return the memoized result of the first call, even if fn is a different
// function.
func (o *once) Do(key any, fn func() error) error {
	_, err := o.m.Do(key, func() (any, error) {
		return nil, fn()
	})
	return err
}
