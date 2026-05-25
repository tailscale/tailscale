// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package backoff

import (
	"testing"
	"time"
)

func TestNewBackoff(t *testing.T) {
	b := NewBackoff("test", nil, 1*time.Second, 30*time.Second)
	if b == nil {
		t.Fatal("NewBackoff returned nil")
	}
}

func TestBackoff_BackOff(t *testing.T) {
	b := NewBackoff("test", nil, 100*time.Millisecond, 1*time.Second)
	
	d := b.BackOff(nil, nil)
	if d < 0 {
		t.Errorf("BackOff returned negative duration: %v", d)
	}
}
