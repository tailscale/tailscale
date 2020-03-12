// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp/derpmap"
	"tailscale.com/stun"
	"tailscale.com/stun/stuntest"
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

func TestBasic(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	defer cleanup()

	c := &Client{
		DERP: derpmap.NewTestWorld(stunAddr),
		Logf: t.Logf,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	r, err := c.GetReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !r.UDP {
		t.Error("want UDP")
	}
	if len(r.DERPLatency) != 1 {
		t.Errorf("expected 1 key in DERPLatency; got %+v", r.DERPLatency)
	}
	if _, ok := r.DERPLatency[stunAddr]; !ok {
		t.Errorf("expected key %q in DERPLatency; got %+v", stunAddr, r.DERPLatency)
	}
	if r.GlobalV4 == "" {
		t.Error("expected GlobalV4 set")
	}
	if r.PreferredDERP != 1 {
		t.Errorf("PreferredDERP = %v; want 1", r.PreferredDERP)
	}
}

func TestWorksWhenUDPBlocked(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to open blackhole STUN listener: %v", err)
	}
	defer blackhole.Close()

	stunAddr := blackhole.LocalAddr().String()
	stunAddr = strings.Replace(stunAddr, "0.0.0.0:", "127.0.0.1:", 1)

	c := &Client{
		DERP: derpmap.NewTestWorld(stunAddr),
		Logf: t.Logf,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	r, err := c.GetReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := &Report{
		DERPLatency: map[string]time.Duration{},
	}

	if !reflect.DeepEqual(r, want) {
		t.Errorf("mismatch\n got: %+v\nwant: %+v\n", r, want)
	}
}
