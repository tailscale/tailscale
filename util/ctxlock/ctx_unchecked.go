// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exports optimized implementation of the [Context] that omits runtime checks.
// It is used when the build tag ts_omit_ctxlock_checks is set.

//go:build ts_omit_ctxlock_checks

package ctxlock

import (
	"context"
	"sync"
)

type Context struct {
	unchecked
}

func None() Context {
	return Context{noneUnchecked}
}

func Wrap(parent context.Context) Context {
	return Context{wrapUnchecked(parent)}
}

func Lock(parent Context, mu *sync.Mutex) Context {
	return Context{lockUnchecked(parent.unchecked, mu)}
}
