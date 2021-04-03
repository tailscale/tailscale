// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nettest

import (
	"context"
	"testing"
)

func TestListener(t *testing.T) {
	l := Listen("srv.local")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
	}()

	if c, err := l.Dial(context.Background(), "tcp", "invalid"); err == nil {
		c.Close()
		t.Fatalf("dial to invalid address succeeded")
	}
	c, err := l.Dial(context.Background(), "tcp", "srv.local")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
		return
	}
	c.Close()
}
