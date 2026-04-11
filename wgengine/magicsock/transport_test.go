// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestTransportMagicIP tests the pluggable transport magic IP block.
func TestTransportMagicIP(t *testing.T) {
	if got := tailcfg.TransportMagicIP(0).String(); got != "127.3.3.41" {
		t.Errorf("TransportMagicIP(0) = %v, want 127.3.3.41", got)
	}

	// Index 0 must be different from the DERP magic IP.
	if tailcfg.TransportMagicIP(0) == tailcfg.DerpMagicIPAddr {
		t.Error("transport magic IP should be different from DERP magic IP")
	}

	// Round-trip index detection.
	for i := range tailcfg.MaxPluggableTransports {
		ip := tailcfg.TransportMagicIP(i)
		idx, ok := tailcfg.IsTransportMagicIP(ip)
		if !ok || idx != i {
			t.Errorf("IsTransportMagicIP(%v) = (%d, %v), want (%d, true)", ip, idx, ok, i)
		}
	}

	// A non-transport address is rejected.
	if _, ok := tailcfg.IsTransportMagicIP(tailcfg.DerpMagicIPAddr); ok {
		t.Error("DERP magic IP should not be a transport magic IP")
	}
	if _, ok := tailcfg.IsTransportMagicIP(netip.MustParseAddr("192.168.1.1")); ok {
		t.Error("a regular IP should not be a transport magic IP")
	}
}

// TestTransportPriorityRanking tests that a transport registered with
// WithPriorityOverDirect beats a direct UDP path, while a default-priority
// transport loses to it.
func TestTransportPriorityRanking(t *testing.T) {
	// Register two transports at distinct magic-IP slots with opposite
	// priorities, then restore the registry so other tests are unaffected.
	saved := registeredTransports
	registeredTransports = []registeredTransport{
		{name: "below", ctor: func(TransportHost) Transport { return nil }, aboveDirect: false},
		{name: "above", ctor: func(TransportHost) Transport { return nil }, aboveDirect: true},
	}
	t.Cleanup(func() { registeredTransports = saved })

	direct := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.168.1.100:41641")}, latency: 10 * time.Millisecond}
	below := addrQuality{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.TransportMagicIP(0), transportMagicPort)}, latency: 50 * time.Millisecond}
	above := addrQuality{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.TransportMagicIP(1), transportMagicPort)}, latency: 50 * time.Millisecond}

	tests := []struct {
		name string
		a, b addrQuality
		want bool
	}{
		{"direct beats below-direct transport", direct, below, true},
		{"below-direct transport loses to direct", below, direct, false},
		{"above-direct transport beats direct", above, direct, true},
		{"direct loses to above-direct transport", direct, above, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := betterAddr(tt.a, tt.b); got != tt.want {
				t.Errorf("betterAddr(%v, %v) = %v, want %v", tt.a.ap, tt.b.ap, got, tt.want)
			}
		})
	}
}

// TestTransportPathPriority tests path preference logic: direct > transport > DERP.
func TestTransportPathPriority(t *testing.T) {
	directV4 := addrQuality{
		epAddr:  epAddr{ap: netip.MustParseAddrPort("192.168.1.100:41641")},
		latency: 10 * time.Millisecond,
	}
	transport := addrQuality{
		epAddr:  epAddr{ap: netip.AddrPortFrom(tailcfg.TransportMagicIP(0), transportMagicPort)},
		latency: 50 * time.Millisecond,
	}
	derp := addrQuality{
		epAddr:  epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)},
		latency: 100 * time.Millisecond,
	}

	tests := []struct {
		name string
		a, b addrQuality
		want bool // true if a is better than b
	}{
		{"direct beats transport", directV4, transport, true},
		{"transport beats DERP", transport, derp, true},
		{"direct beats DERP", directV4, derp, true},
		{"DERP loses to transport", derp, transport, false},
		{"transport loses to direct", transport, directV4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := betterAddr(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("betterAddr(%v, %v) = %v, want %v", tt.a.ap, tt.b.ap, got, tt.want)
			}
		})
	}
}

// TestTransportPathSelection tests iterated path selection with a transport in the mix.
func TestTransportPathSelection(t *testing.T) {
	tests := []struct {
		name     string
		paths    []addrQuality
		wantBest string
	}{
		{
			name: "direct_beats_all",
			paths: []addrQuality{
				{epAddr: epAddr{ap: netip.MustParseAddrPort("1.2.3.4:1234")}},
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.TransportMagicIP(0), transportMagicPort)}},
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}},
			},
			wantBest: "1.2.3.4:1234",
		},
		{
			name: "transport_beats_derp",
			paths: []addrQuality{
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.TransportMagicIP(0), transportMagicPort)}},
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}},
			},
			wantBest: "127.3.3.41:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			best := tt.paths[0]
			for _, path := range tt.paths[1:] {
				if betterAddr(path, best) {
					best = path
				}
			}
			if best.ap.String() != tt.wantBest {
				t.Errorf("Best path = %v, want %v", best.ap, tt.wantBest)
			}
		})
	}
}

// TestTransportReadResult tests the transportReadResult structure.
func TestTransportReadResult(t *testing.T) {
	nodeKey := key.NewNode()
	testData := []byte("test packet data")

	result := transportReadResult{
		transportIdx: 0,
		n:            len(testData),
		src:          nodeKey.Public(),
		buf:          testData,
	}

	if result.n != len(testData) {
		t.Errorf("result.n = %d, want %d", result.n, len(testData))
	}
	if result.src != nodeKey.Public() {
		t.Errorf("result.src mismatch")
	}
	if string(result.buf) != string(testData) {
		t.Errorf("result.buf = %q, want %q", result.buf, testData)
	}
}

// TestDiscoRXPathTransport tests the transport disco path constant.
func TestDiscoRXPathTransport(t *testing.T) {
	if discoRXPathTransport != "transport" {
		t.Errorf("discoRXPathTransport = %q, want %q", discoRXPathTransport, "transport")
	}
	if discoRXPathTransport == discoRXPathDERP {
		t.Error("transport path should be different from DERP path")
	}
	if discoRXPathTransport == discoRXPathUDP {
		t.Error("transport path should be different from UDP path")
	}
}

// TestTransportMetrics tests that transport metrics are properly defined.
func TestTransportMetrics(t *testing.T) {
	if metricRecvDataPacketsTransport == nil {
		t.Error("metricRecvDataPacketsTransport should be initialized")
	}
	if metricRecvDataBytesTransport == nil {
		t.Error("metricRecvDataBytesTransport should be initialized")
	}
	if metricSendDataPacketsTransport == nil {
		t.Error("metricSendDataPacketsTransport should be initialized")
	}
	if metricSendDataBytesTransport == nil {
		t.Error("metricSendDataBytesTransport should be initialized")
	}
}

// TestPathTransportConstant tests the PathTransport constant.
func TestPathTransportConstant(t *testing.T) {
	if PathTransport != "transport" {
		t.Errorf("PathTransport = %q, want %q", PathTransport, "transport")
	}
	if PathTransport == PathDERP {
		t.Error("PathTransport should be different from PathDERP")
	}
	if PathTransport == PathDirectIPv4 {
		t.Error("PathTransport should be different from PathDirectIPv4")
	}
}
