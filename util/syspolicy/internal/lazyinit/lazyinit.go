// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The lazyinit package facilitates deferred package initialization.
package lazyinit

import (
	"sync"
	"sync/atomic"
)

var packageInit deferredOnce

// Defer defers the specified action until [Do] is called.
// It returns a boolean indicating whether [Do] has already been called.
func Defer(action func() error) bool {
	return packageInit.Defer(action)
}

// DeferWithCleanup is like [Defer], but the action function returns a cleanup
// function to be called in case of an error.
func DeferWithCleanup(action func() (cleanup func(), err error)) bool {
	return packageInit.DeferWithCleanup(action)
}

// Do runs all deferred functions and returns an error if any of them fail.
func Do() error {
	return packageInit.Do()
}

type deferredOnce struct {
	done  atomic.Uint32
	err   error
	m     sync.Mutex
	funcs []func() (cleanup func(), err error)
}

func (o *deferredOnce) Defer(action func() error) bool {
	return o.DeferWithCleanup(func() (cleanup func(), err error) {
		return nil, action()
	})
}

func (o *deferredOnce) DeferWithCleanup(action func() (cleanup func(), err error)) bool {
	o.m.Lock()
	defer o.m.Unlock()
	if o.done.Load() != 0 {
		return false
	}
	o.funcs = append(o.funcs, action)
	return true
}

func (o *deferredOnce) Do() error {
	if o.done.Load() == 0 {
		o.doSlow()
	}
	return o.err
}

func (o *deferredOnce) doSlow() (err error) {
	o.m.Lock()
	defer o.m.Unlock()
	if o.done.Load() == 0 {
		defer func() {
			o.done.Store(1)
			o.err = err
		}()
		for _, f := range o.funcs {
			cleanup, err := f()
			if err != nil {
				return err
			}
			if cleanup != nil {
				defer func() {
					if err != nil {
						cleanup()
					}
				}()
			}
		}
	}
	return o.err
}
