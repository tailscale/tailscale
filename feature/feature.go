// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package feature tracks which features are linked into the binary.
package feature

import (
	"errors"
	"reflect"

	"tailscale.com/util/testenv"
)

var ErrUnavailable = errors.New("feature not included in this build")

var in = map[string]bool{}

// Registered reports the set of registered features.
//
// The returned map should not be modified by the caller,
// not accessed concurrently with calls to Register.
func Registered() map[string]bool { return in }

// IsRegistered reports whether the named feature package's init
// function has run and registered itself via [Register] in this
// binary. It is distinct from the compile-time [buildfeatures]
// constants: a feature package can be present in the binary but not
// imported (e.g. tsnet deliberately does not import many features),
// in which case its init does not run.
func IsRegistered(name string) bool { return in[name] }

// Register notes that the named feature is linked into the binary and
// reports whether it should initialize itself. It reports false if the
// feature was disabled via the TS_DISABLE_FEATURE environment variable,
// in which case the feature is not recorded as registered and the
// caller should skip the rest of its registration, such as setting
// hooks and registering extensions and handlers. The typical use is at
// the top of a feature package's init:
//
//	func init() {
//		if !feature.Register("foo") {
//			return
//		}
//		// ... set hooks, register extensions and handlers ...
//	}
//
// A feature package with more than one init that registers things puts
// this gate in one of them and guards the others with [Disabled], or
// better, consolidates them into a single init.
//
// Register panics if the feature is already registered.
func Register(name string) bool {
	if Disabled(name) {
		return false
	}
	if _, ok := in[name]; ok {
		panic("duplicate feature registration for " + name)
	}
	in[name] = true
	return true
}

// Hook is a func that can only be set once.
//
// It is not safe for concurrent use.
type Hook[Func any] struct {
	f  Func
	ok bool
}

// IsSet reports whether the hook has been set.
func (h *Hook[Func]) IsSet() bool {
	return h.ok
}

// Set sets the hook function, panicking if it's already been set
// or f is the zero value.
//
// It's meant to be called in init.
//
// As a backstop for feature packages that forget to consult
// [Register], if the caller is a package under tailscale.com/feature/
// whose feature was disabled via TS_DISABLE_FEATURE, the call is
// silently ignored and the hook is left unset.
func (h *Hook[Func]) Set(f Func) {
	if callerFeatureDisabled() {
		return
	}
	if h.ok {
		panic("Set on already-set feature hook")
	}
	if reflect.ValueOf(f).IsZero() {
		panic("Set with zero value")
	}
	h.f = f
	h.ok = true
}

// SetForTest sets the hook function for tests, blowing
// away any previous value. It will panic if called from
// non-test code.
//
// It returns a restore function that resets the hook
// to its previous value.
func (h *Hook[Func]) SetForTest(f Func) (restore func()) {
	testenv.AssertInTest()
	old := *h
	h.f, h.ok = f, true
	return func() { *h = old }
}

// Get returns the hook function, or panics if it hasn't been set.
// Use IsSet to check if it's been set, or use GetOrNil if you're
// okay with a nil return value.
func (h *Hook[Func]) Get() Func {
	if !h.ok {
		panic("Get on unset feature hook, without IsSet")
	}
	return h.f
}

// GetOk returns the hook function and true if it has been set,
// otherwise its zero value and false.
func (h *Hook[Func]) GetOk() (f Func, ok bool) {
	return h.f, h.ok
}

// GetOrNil returns the hook function or nil if it hasn't been set.
func (h *Hook[Func]) GetOrNil() Func {
	return h.f
}

// Hooks is a slice of funcs.
//
// As opposed to a single Hook, this is meant to be used when
// multiple parties are able to install the same hook.
type Hooks[Func any] []Func

// Add adds a hook to the list of hooks.
//
// Add should only be called during early program
// startup before Tailscale has started.
// It is not safe for concurrent use.
//
// Like [Hook.Set], it is silently ignored if the calling feature
// package was disabled via TS_DISABLE_FEATURE.
func (h *Hooks[Func]) Add(f Func) {
	if callerFeatureDisabled() {
		return
	}
	if reflect.ValueOf(f).IsZero() {
		panic("Add with zero value")
	}
	*h = append(*h, f)
}
