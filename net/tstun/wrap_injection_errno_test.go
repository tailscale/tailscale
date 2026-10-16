// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !tamago

package tstun

import (
	"errors"
	"syscall"
	"testing"
)

// ErrInjectionQueueFull must match the platform ENOBUFS errno, so callers
// can test for buffer exhaustion without knowing this package's type.
func TestErrInjectionQueueFullMatchesENOBUFS(t *testing.T) {
	if !errors.Is(ErrInjectionQueueFull, syscall.ENOBUFS) {
		t.Errorf("errors.Is(ErrInjectionQueueFull, syscall.ENOBUFS) = false, want true")
	}
}
