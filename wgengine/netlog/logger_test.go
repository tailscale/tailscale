// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netlog

import (
	"testing"
	"time"
)

func TestLogger(t *testing.T) {
	logger := NewLogger(nil, nil)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
}

func TestMessage(t *testing.T) {
	m := Message{
		Start: time.Now(),
	}
	if m.Start.IsZero() {
		t.Error("Message.Start is zero")
	}
}
