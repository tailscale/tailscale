// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_tsync_test

package tsync

import "sync"

type Mutex = sync.Mutex
