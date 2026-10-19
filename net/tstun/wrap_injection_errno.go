// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !tamago

package tstun

import (
	"fmt"
	"syscall"
)

// ErrInjectionQueueFull is returned when a full injection queue forced a
// best-effort packet to be dropped rather than queued. It wraps
// syscall.ENOBUFS, the platform's "no buffer space available" errno, so
// callers can test for buffer exhaustion without knowing this package's
// type:
//
//	errors.Is(err, syscall.ENOBUFS)
//
// Dropped packets are already counted as reason="queue_full" in the
// tailscaled_outbound_dropped_packets_total usermetric, so callers need not
// log this error.
var ErrInjectionQueueFull = fmt.Errorf("injection queue full: %w", syscall.ENOBUFS)
