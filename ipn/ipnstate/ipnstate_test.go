// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnstate

import (
	"testing"
)

func TestStatus(t *testing.T) {
	s := &Status{}
	if s == nil {
		t.Fatal("new Status is nil")
	}
}

func TestPeerStatus(t *testing.T) {
	ps := &PeerStatus{}
	if ps == nil {
		t.Fatal("new PeerStatus is nil")
	}
}

func TestStatusBuilder(t *testing.T) {
	sb := &StatusBuilder{}
	s := sb.Status()
	if s == nil {
		t.Fatal("StatusBuilder.Status() returned nil")
	}
}
