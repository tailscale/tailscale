// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rsop

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

// ErrAlreadyConsumed is the error returned when [StoreRegistration.ReplaceStore]
// or [StoreRegistration.Unregister] is called more than once.
var ErrAlreadyConsumed = errors.New("the store registration is no longer valid")

// StoreRegistration is a [source.Store] registered for use in the specified scope.
// It can be used to unregister the store, or replace it with another one.
type StoreRegistration struct {
	source   *source.Source
	m        sync.Mutex  // protects the [StoreRegistration.consumeSlow] path
	consumed atomic.Bool // can be read without holding m, but must be written with m held
}

// RegisterStore registers a new policy [source.Store] with the specified name and [setting.PolicyScope].
func RegisterStore(name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	return newStoreRegistration(name, scope, store)
}

// RegisterStoreForTest is like [RegisterStore], but unregisters the store when
// tb and all its subtests complete.
func RegisterStoreForTest(tb internal.TB, name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	setForTest(tb, &policyReloadMinDelay, 10*time.Millisecond)
	setForTest(tb, &policyReloadMaxDelay, 500*time.Millisecond)

	reg, err := RegisterStore(name, scope, store)
	if err == nil {
		tb.Cleanup(func() {
			if err := reg.Unregister(); err != nil && !errors.Is(err, ErrAlreadyConsumed) {
				tb.Fatalf("Unregister failed: %v", err)
			}
		})
	}
	return reg, err // may be nil or non-nil
}

func newStoreRegistration(name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	source := source.NewSource(name, scope, store)
	if err := registerSource(source); err != nil {
		return nil, err
	}
	return &StoreRegistration{source: source}, nil
}

// ReplaceStore replaces the registered store with the new one,
// returning a new [StoreRegistration] or an error.
func (r *StoreRegistration) ReplaceStore(new source.Store) (*StoreRegistration, error) {
	var res *StoreRegistration
	err := r.consume(func() error {
		newSource := source.NewSource(r.source.Name(), r.source.Scope(), new)
		if err := replaceSource(r.source, newSource); err != nil {
			return err
		}
		res = &StoreRegistration{source: newSource}
		return nil
	})
	return res, err
}

// Unregister reverts the registration.
func (r *StoreRegistration) Unregister() error {
	return r.consume(func() error { return unregisterSource(r.source) })
}

// consume invokes fn, consuming r if no error is returned.
// It returns [ErrAlreadyConsumed] on subsequent calls after the first successful call.
func (r *StoreRegistration) consume(fn func() error) (err error) {
	if r.consumed.Load() {
		return ErrAlreadyConsumed
	}
	return r.consumeSlow(fn)
}

func (r *StoreRegistration) consumeSlow(fn func() error) (err error) {
	r.m.Lock()
	defer r.m.Unlock()
	if r.consumed.Load() {
		return ErrAlreadyConsumed
	}
	if err = fn(); err == nil {
		r.consumed.Store(true)
	}
	return err // may be nil or non-nil
}
