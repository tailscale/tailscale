// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"testing"

	"tailscale.com/net/stun"
)

func TestProdAutocertHostPolicy(t *testing.T) {
	tests := []struct {
		in     string
		wantOK bool
	}{
		{"derp.tailscale.com", true},
		{"derp.tailscale.com.", true},
		{"derp1.tailscale.com", true},
		{"derp1b.tailscale.com", true},
		{"derp2.tailscale.com", true},
		{"derp02.tailscale.com", true},
		{"derp-nyc.tailscale.com", true},
		{"derpfoo.tailscale.com", true},
		{"derp02.bar.tailscale.com", false},
		{"example.net", false},
	}
	for _, tt := range tests {
		got := prodAutocertHostPolicy(context.Background(), tt.in) == nil
		if got != tt.wantOK {
			t.Errorf("f(%q) = %v; want %v", tt.in, got, tt.wantOK)
		}
	}
}

func BenchmarkServerSTUN(b *testing.B) {
	b.ReportAllocs()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serverSTUNListener(ctx, pc.(*net.UDPConn))
	addr := pc.LocalAddr().(*net.UDPAddr)

	var resBuf [1500]byte
	cc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}

	tx := stun.NewTxID()
	req := stun.Request(tx)
	for i := 0; i < b.N; i++ {
		if _, err := cc.WriteToUDP(req, addr); err != nil {
			b.Fatal(err)
		}
		_, _, err := cc.ReadFromUDP(resBuf[:])
		if err != nil {
			b.Fatal(err)
		}
	}

}
