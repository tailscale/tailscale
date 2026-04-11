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

// TestWebRTCMagicIP tests the WebRTC magic IP constant.
func TestWebRTCMagicIP(t *testing.T) {
	if tailcfg.WebRTCMagicIPAddr.String() != "127.3.3.41" {
		t.Errorf("WebRTC magic IP = %v, want 127.3.3.41", tailcfg.WebRTCMagicIPAddr)
	}

	// Verify it's different from DERP magic IP
	if tailcfg.WebRTCMagicIPAddr == tailcfg.DerpMagicIPAddr {
		t.Error("WebRTC magic IP should be different from DERP magic IP")
	}
}

// TestWebRTCPathPriority tests path preference logic: direct > WebRTC > DERP.
func TestWebRTCPathPriority(t *testing.T) {
	directV4 := addrQuality{
		epAddr:  epAddr{ap: netip.MustParseAddrPort("192.168.1.100:41641")},
		latency: 10 * time.Millisecond,
	}
	webrtc := addrQuality{
		epAddr:  epAddr{ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, webrtcMagicPort)},
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
		{"direct beats WebRTC", directV4, webrtc, true},
		{"WebRTC beats DERP", webrtc, derp, true},
		{"direct beats DERP", directV4, derp, true},
		{"DERP loses to WebRTC", derp, webrtc, false},
		{"WebRTC loses to direct", webrtc, directV4, false},
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

// TestWebRTCPathSelection tests iterated path selection with WebRTC in the mix.
func TestWebRTCPathSelection(t *testing.T) {
	tests := []struct {
		name     string
		paths    []addrQuality
		wantBest string
	}{
		{
			name: "direct_beats_all",
			paths: []addrQuality{
				{epAddr: epAddr{ap: netip.MustParseAddrPort("1.2.3.4:1234")}},
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, webrtcMagicPort)}},
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}},
			},
			wantBest: "1.2.3.4:1234",
		},
		{
			name: "webrtc_beats_derp",
			paths: []addrQuality{
				{epAddr: epAddr{ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, webrtcMagicPort)}},
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

// TestWebRTCReadResult tests the webrtcReadResult structure.
func TestWebRTCReadResult(t *testing.T) {
	nodeKey := key.NewNode()
	testData := []byte("test packet data")

	result := webrtcReadResult{
		n:   len(testData),
		src: nodeKey.Public(),
		buf: testData,
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

// TestDiscoRXPathWebRTC tests the WebRTC disco path constant.
func TestDiscoRXPathWebRTC(t *testing.T) {
	if discoRXPathWebRTC != "WebRTC" {
		t.Errorf("discoRXPathWebRTC = %q, want %q", discoRXPathWebRTC, "WebRTC")
	}
	if discoRXPathWebRTC == discoRXPathDERP {
		t.Error("WebRTC path should be different from DERP path")
	}
	if discoRXPathWebRTC == discoRXPathUDP {
		t.Error("WebRTC path should be different from UDP path")
	}
}

// TestWebRTCMetrics tests that WebRTC metrics are properly defined.
func TestWebRTCMetrics(t *testing.T) {
	if metricRecvDataPacketsWebRTC == nil {
		t.Error("metricRecvDataPacketsWebRTC should be initialized")
	}
	if metricRecvDataBytesWebRTC == nil {
		t.Error("metricRecvDataBytesWebRTC should be initialized")
	}
	if metricSendDataPacketsWebRTC == nil {
		t.Error("metricSendDataPacketsWebRTC should be initialized")
	}
	if metricSendDataBytesWebRTC == nil {
		t.Error("metricSendDataBytesWebRTC should be initialized")
	}
}

// TestPathWebRTCConstant tests the PathWebRTC constant.
func TestPathWebRTCConstant(t *testing.T) {
	if PathWebRTC != "webrtc" {
		t.Errorf("PathWebRTC = %q, want %q", PathWebRTC, "webrtc")
	}
	if PathWebRTC == PathDERP {
		t.Error("PathWebRTC should be different from PathDERP")
	}
	if PathWebRTC == PathDirectIPv4 {
		t.Error("PathWebRTC should be different from PathDirectIPv4")
	}
}
