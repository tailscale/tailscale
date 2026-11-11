// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import "testing"

func TestBypassControlNoop(t *testing.T) {
	if err := bypassControlFunc(t.Context(), "tcp4", "192.0.2.1:80", nil); err != nil {
		t.Fatalf("non-Linux bypass hook: %v", err)
	}
}
