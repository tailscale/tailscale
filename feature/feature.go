// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package feature tracks which features are linked into the binary.
package feature

import "reflect"

var in = map[string]bool{}

// Register notes that the named feature is linked into the binary.
func Register(name string) {
	if _, ok := in[name]; ok {
		panic("duplicate feature registration for " + name)
	}
	in[name] = true
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
func (h *Hook[Func]) Set(f Func) {
	if h.ok {
		panic("Set on already-set feature hook")
	}
	if reflect.ValueOf(f).IsZero() {
		panic("Set with zero value")
	}
	h.f = f
	h.ok = true
}

// Get returns the hook function, or panics if it hasn't been set.
// Use IsSet to check if it's been set.
func (h *Hook[Func]) Get() Func {
	if !h.ok {
		panic("Get on unset feature hook, without IsSet")
	}
	return h.f
}
