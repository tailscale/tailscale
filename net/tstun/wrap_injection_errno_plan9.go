// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9 || tamago

package tstun

import "errors"

// ErrInjectionQueueFull is returned when a full injection queue forced a
// best-effort packet to be dropped rather than queued. On platforms whose
// syscall package has no ENOBUFS, it matches nothing but itself.
var ErrInjectionQueueFull = errors.New("injection queue full")
