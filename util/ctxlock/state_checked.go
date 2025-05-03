// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exports default, unoptimized implementation of the [State] that includes runtime checks.
// It is used unless the build tag ts_omit_ctxlock_checks is set.

//go:build !ts_omit_ctxlock_checks

package ctxlock

import (
	"context"
	"sync"
)

// Checked indicates whether runtime checks are enabled for this package.
const Checked = true

// State carries the lock state of zero or more mutexes and an optional [context.Context].
// Its zero value is valid and represents an unlocked state and an empty context.
//
// Calling [Lock] returns a derived State with the specified mutex locked. The State is considered
// the owner of the lock if it wasn't already acquired by a parent State. Calling [State.Unlock]
// releases the lock owned by the state. It is a runtime error to call Unlock more than once,
// to use the State after it has been unlocked, or to unlock a parent State before its child.
type State struct {
	*checked
}

// None returns a [State] that carries no lock state and an empty [context.Context].
func None() State {
	return State{}
}

// FromContext returns a [State] that carries the same lock state as the provided [context.Context].
//
// It is typically used by methods that already accept a [context.Context] for cancellation or deadline
// management, and would like to use it for locking as well.
func FromContext(ctx context.Context) State {
	return State{fromContextChecked(ctx)}
}

// Lock acquires the specified mutex and becomes its owner, unless it is already held by a parent.
// The parent can be either a [State] or a [context.Context]. A zero [State] is a valid parent.
// It returns a new [State] that augments the parent with the additional lock state.
//
// It is a runtime error to pass a nil mutex or to unlock the parent state before the returned one.
func Lock[T context.Context](parent T, mu *sync.Mutex) State {
	if parent, ok := any(parent).(State); ok {
		return State{lockChecked(parent.checked, mu)}
	}
	return State{lockChecked(fromContextChecked(parent), mu)}
}
