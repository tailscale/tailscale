// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exports optimized implementations of the [Context] that omit runtime checks.
// It is used when the build tag ts_omit_ctxlock_checks is set.

//go:build ts_omit_ctxlock_checks

package ctxlock

import (
	"context"
	"sync"
)

type Context[T sync.Locker] struct {
	unchecked[T]
}

func None[T sync.Locker]() Context[T] {
	return Context[T]{noneUnchecked[T]()}
}

func Wrap[T sync.Locker](parent context.Context) Context[T] {
	return Context[T]{wrapUnchecked[T](parent)}
}

func Lock[T, P sync.Locker](parent Context[P], mu T) Context[T] {
	return Context[T]{lockUnchecked(parent.unchecked, mu)}
}
