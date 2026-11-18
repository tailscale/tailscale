// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDialContext(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := NewDetector(t.Logf)
	c, err := d.dialContext(t.Context(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if c, err := d.dialContext(ctx, "tcp4", ln.Addr().String()); !errors.Is(err, context.Canceled) {
		if c != nil {
			c.Close()
		}
		t.Errorf("canceled dial error = %v; want context.Canceled", err)
	}
}
