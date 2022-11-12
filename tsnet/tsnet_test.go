// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsnet

import (
	"errors"
	"testing"
)

// TestListener_Server ensures that the listener type always keeps the Server
// method, which is used by some external applications to identify a tsnet.Listener
// from other net.Listeners, as well as access the underlying Server.
func TestListener_Server(t *testing.T) {
	s := &Server{}
	ln := listener{s: s}
	if ln.Server() != s {
		t.Errorf("listener.Server() returned %v, want %v", ln.Server(), s)
	}
}

func TestListenerPort(t *testing.T) {
	errNone := errors.New("sentinel start error")

	tests := []struct {
		network string
		addr    string
		wantErr bool
	}{
		{"tcp", ":80", false},
		{"foo", ":80", true},
		{"tcp", ":http", false},  // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":https", false}, // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":gibberishsdlkfj", true},
		{"tcp", ":%!d(string=80)", true}, // issue 6201
	}
	for _, tt := range tests {
		s := &Server{}
		s.initOnce.Do(func() { s.initErr = errNone })
		_, err := s.Listen(tt.network, tt.addr)
		gotErr := err != nil && err != errNone
		if gotErr != tt.wantErr {
			t.Errorf("Listen(%q, %q) error = %v, want %v", tt.network, tt.addr, gotErr, tt.wantErr)
		}
	}
}
