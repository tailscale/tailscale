// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exports optimized implementation of the [State] that omits runtime checks.
// It is used when the build tag ts_omit_ctxlock_checks is set.

//go:build ts_omit_ctxlock_checks

package ctxlock

import (
	"context"
	"sync"
)

const Checked = false

type State struct {
	unchecked
}

func None() State {
	return State{}
}

func FromContext(parent context.Context) State {
	return State{fromContextUnchecked(parent)}
}

func Lock[T context.Context](parent T, mu *sync.Mutex) State {
	if parent, ok := any(parent).(State); ok {
		return State{lockUnchecked(parent.unchecked, mu)}
	}
	return State{lockUnchecked(fromContextUnchecked(parent), mu)}
}
