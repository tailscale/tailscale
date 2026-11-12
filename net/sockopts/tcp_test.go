// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sockopts

import (
	"net"
	"testing"
	"time"
)

func TestTCPConfigNoop(t *testing.T) {
	// A zero configuration must not even access the socket.
	result := (TCPConfig{}).Apply(new(net.TCPConn))
	if result.KeepAlive != nil || result.UserTimeout != nil {
		t.Fatalf("zero config: %+v", result)
	}
}

func TestTCPConfigErrors(t *testing.T) {
	timeout := time.Second
	for _, enable := range []bool{false, true} {
		cfg := TCPConfig{
			KeepAlive:   &net.KeepAliveConfig{Enable: enable},
			UserTimeout: &timeout,
		}
		// Both operations fail on an uninitialized connection. The second
		// must still be attempted when the first fails.
		result := cfg.Apply(new(net.TCPConn))
		if result.KeepAlive == nil || result.UserTimeout == nil {
			t.Errorf("enable=%v: %+v; want both errors", enable, result)
		}
	}
}
