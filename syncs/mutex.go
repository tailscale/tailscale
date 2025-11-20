// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_mutex_debug

package syncs

import "sync"

// Mutex is an alias for sync.Mutex.
//
// It's only not a sync.Mutex when built with the ts_mutex_debug build tag.
type Mutex = sync.Mutex

// RWMutex is an alias for sync.RWMutex.
//
// It's only not a sync.RWMutex when built with the ts_mutex_debug build tag.
type RWMutex = sync.RWMutex

// RequiresMutex declares the caller assumes it has the given
// mutex held. In non-debug builds, it's a no-op and compiles to
// nothing.
func RequiresMutex(mu *sync.Mutex) {}
