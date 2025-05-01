// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exports default, unoptimized implementations of the [Context] that include runtime checks.
// It is used unless the build tag ts_omit_ctxlock_checks is set.

//go:build !ts_omit_ctxlock_checks

package ctxlock

import (
	"context"
	"sync"
)

// Context is a [context.Context] that can carry a [sync.Mutex] lock state.
// Calling [Context.Unlock] on a [Context] unlocks the mutex locked by the context, if any.
// It is a runtime error to call [Context.Unlock] more than once,
// or use a [Context] after calling [Context.Unlock].
type Context[T sync.Locker] struct {
	*checked[T]
}

// None returns a [Context] that carries no mutex lock state and an empty [context.Context].
//
// It is typically used by top-level callers that do not have a parent context to pass in,
// and is a shorthand for [Context]([context.Background]).
func None[T sync.Locker]() Context[T] {
	return Context[T]{noneChecked[T]()}
}

// Wrap returns a derived [Context] that wraps the provided [context.Context].
//
// It is typically used by callers that already have a [context.Context],
// which may or may not be a [Context] tracking a mutex lock state.
func Wrap[T sync.Locker](parent context.Context) Context[T] {
	return Context[T]{wrapChecked[T](parent)}
}

// Lock returns a derived [Context] that wraps the provided [context.Context]
// and carries the mutex lock state.
//
// It locks the mutex unless it is already held by the parent or an ancestor [Context].
// It is a runtime error to pass a nil mutex or to unlock the parent context
// before the returned one.
func Lock[T, P sync.Locker](parent Context[P], mu T) Context[T] {
	return Context[T]{lockChecked(parent.checked, mu)}
}
