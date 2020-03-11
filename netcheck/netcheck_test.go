// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"net"
	"testing"

	"tailscale.com/stun"
)

func TestHairpinSTUN(t *testing.T) {
	c := &Client{
		hairTX:      stun.NewTxID(),
		gotHairSTUN: make(chan *net.UDPAddr, 1),
	}
	req := stun.Request(c.hairTX)
	if !stun.Is(req) {
		t.Fatal("expected STUN message")
	}
	if !c.handleHairSTUN(req, nil) {
		t.Fatal("expected true")
	}
	select {
	case <-c.gotHairSTUN:
	default:
		t.Fatal("expected value")
	}
}
