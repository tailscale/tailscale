// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_mutex_debug

package syncs

import "sync"

type Mutex struct {
	sync.Mutex
}

type RWMutex struct {
	sync.RWMutex
}

func RequiresMutex(mu *sync.Mutex) {
	// TODO: check
}

// TODO(bradfitz): actually track stuff when in debug mode.
