// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"syscall"
	"testing"

	"tailscale.com/net/netmon"
)

func TestBypassControlError(t *testing.T) {
	if _, err := netmon.DefaultRouteInterface(); err != nil {
		t.Skipf("no default interface: %v", err)
	}
	wantErr := errors.New("raw socket control failed")
	raw := &bypassTestRawConn{err: wantErr}
	if err := bypassControlFunc(t.Context(), "tcp4", "192.0.2.1:80", raw); !errors.Is(err, wantErr) {
		t.Errorf("hook error = %v; want raw socket error", err)
	}
	if raw.calls != 1 {
		t.Errorf("RawConn.Control calls = %d; want 1", raw.calls)
	}
}

type bypassTestRawConn struct {
	syscall.RawConn
	err   error
	calls int
}

func (c *bypassTestRawConn) Control(func(uintptr)) error {
	c.calls++
	return c.err
}
