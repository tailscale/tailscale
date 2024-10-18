// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr string
	}{
		{
			name: "simple",
			setup: func(c *Config) {
				c.AddNode(c.AddNetwork("2.1.1.1", "192.168.1.1/24", EasyNAT, NATPMP))
				c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", HardNAT))
			},
		},
		{
			name: "latency-and-loss",
			setup: func(c *Config) {
				n1 := c.AddNetwork("2.1.1.1", "192.168.1.1/24", EasyNAT, NATPMP)
				n1.SetLatency(time.Second)
				n1.SetPacketLoss(0.1)
				c.AddNode(n1)
				c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", HardNAT))
			},
		},
		{
			name: "indirect",
			setup: func(c *Config) {
				n1 := c.AddNode(c.AddNetwork("2.1.1.1", "192.168.1.1/24", HardNAT))
				n1.Network().AddService(NATPMP)
				c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", NAT("hard")))
			},
		},
		{
			name: "multi-node-in-net",
			setup: func(c *Config) {
				net1 := c.AddNetwork("2.1.1.1", "192.168.1.1/24")
				c.AddNode(net1)
				c.AddNode(net1)
			},
		},
		{
			name: "dup-wan-ip",
			setup: func(c *Config) {
				c.AddNetwork("2.1.1.1", "192.168.1.1/24")
				c.AddNetwork("2.1.1.1", "10.2.0.1/16")
			},
			wantErr: "two networks have the same WAN IP 2.1.1.1; Anycast not (yet?) supported",
		},
		{
			name: "one-to-one-nat-with-multiple-nodes",
			setup: func(c *Config) {
				net1 := c.AddNetwork("2.1.1.1", "192.168.1.1/24", One2OneNAT)
				c.AddNode(net1)
				c.AddNode(net1)
			},
			wantErr: "error creating NAT type \"one2one\" for network 2.1.1.1: can't use one2one NAT type on networks other than single-node networks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Config
			tt.setup(&c)
			_, err := New(&c)
			if err == nil {
				if tt.wantErr == "" {
					return
				}
				t.Fatalf("got success; wanted error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("got error %q; want %q", err, tt.wantErr)
			}
		})
	}
}

func TestNodeString(t *testing.T) {
	if g, w := (&Node{num: 1}).String(), "node1"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if g, w := (&node{num: 1}).String(), "node1"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
}
