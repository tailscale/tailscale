// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lazy

import (
	"sync"
	"sync/atomic"

	"tailscale.com/types/ptr"
)

// DeferredInit allows one or more funcs to be deferred
// until [DeferredInit.Do] is called for the first time.
//
// DeferredInit is safe for concurrent use.
type DeferredInit struct {
	DeferredFuncs
}

// DeferredFuncs allows one or more funcs to be deferred
// until the owner's [DeferredInit.Do] method is called
// for the first time.
//
// DeferredFuncs is safe for concurrent use.
type DeferredFuncs struct {
	m     sync.Mutex
	funcs []func() error

	// err is either:
	//    * nil, if deferred init has not yet been completed
	//    * nilErrPtr, if initialization completed successfully
	//    * non-nil and not nilErrPtr, if there was an error
	//
	// It is an atomic.Pointer so it can be read without m held.
	err atomic.Pointer[error]
}

// Defer adds a function to be called when [DeferredInit.Do]
// is called for the first time. It returns true on success,
// or false if [DeferredInit.Do] has already been called.
func (d *DeferredFuncs) Defer(f func() error) bool {
	d.m.Lock()
	defer d.m.Unlock()
	if d.err.Load() != nil {
		return false
	}
	d.funcs = append(d.funcs, f)
	return true
}

// MustDefer is like [DeferredFuncs.Defer], but panics
// if [DeferredInit.Do] has already been called.
func (d *DeferredFuncs) MustDefer(f func() error) {
	if !d.Defer(f) {
		panic("deferred init already completed")
	}
}

// Do calls previously deferred init functions if it is being called
// for the first time on this instance of [DeferredInit].
// It stops and returns an error if any init function returns an error.
//
// It is safe for concurrent use, and the deferred init is guaranteed
// to have been completed, either successfully or with an error,
// when Do() returns.
func (d *DeferredInit) Do() error {
	err := d.err.Load()
	if err == nil {
		err = d.doSlow()
	}
	return *err
}

func (d *DeferredInit) doSlow() (err *error) {
	d.m.Lock()
	defer d.m.Unlock()
	if err := d.err.Load(); err != nil {
		return err
	}
	defer func() {
		d.err.Store(err)
		d.funcs = nil // do not keep funcs alive after invoking
	}()
	for _, f := range d.funcs {
		if err := f(); err != nil {
			return ptr.To(err)
		}
	}
	return nilErrPtr
}

// Funcs is a shorthand for &d.DeferredFuncs.
// The returned value can safely be passed to external code,
// allowing to defer init funcs without also exposing [DeferredInit.Do].
func (d *DeferredInit) Funcs() *DeferredFuncs {
	return &d.DeferredFuncs
}
