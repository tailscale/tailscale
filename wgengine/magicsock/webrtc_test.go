// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"tailscale.com/rtclib"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestSignalingMessageEncoding tests JSON encoding/decoding of signaling messages
func TestSignalingMessageEncoding(t *testing.T) {
	disco1 := key.NewDisco()
	disco2 := key.NewDisco()

	tests := []struct {
		name string
		msg  rtclib.SignalingMessage
	}{
		{
			name: "offer",
			msg: rtclib.SignalingMessage{
				Type:  rtclib.MessageTypeOffer,
				From:  disco1.Public().String(),
				To:    disco2.Public().String(),
				Offer: &webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: "v=0..."},
			},
		},
		{
			name: "answer",
			msg: rtclib.SignalingMessage{
				Type:   rtclib.MessageTypeAnswer,
				From:   disco2.Public().String(),
				To:     disco1.Public().String(),
				Answer: &webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: "v=0..."},
			},
		},
		{
			name: "candidate",
			msg: rtclib.SignalingMessage{
				Type:      rtclib.MessageTypeCandidate,
				From:      disco1.Public().String(),
				To:        disco2.Public().String(),
				Candidate: &webrtc.ICECandidateInit{Candidate: "..."},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := json.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Decode
			var decoded rtclib.SignalingMessage
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Verify
			if decoded.Type != tt.msg.Type {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, tt.msg.Type)
			}
			if decoded.From != tt.msg.From {
				t.Errorf("From mismatch: got %v, want %v", decoded.From, tt.msg.From)
			}
			if decoded.To != tt.msg.To {
				t.Errorf("To mismatch: got %v, want %v", decoded.To, tt.msg.To)
			}
		})
	}
}

// mockSignalHandler is a test implementation of rtclib.SignalHandler
type mockSignalHandler struct {
	offerCount     int
	answerCount    int
	candidateCount int
	mu             sync.Mutex
}

func (m *mockSignalHandler) HandleOffer(from, to string, offer *webrtc.SessionDescription) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.offerCount++
}

func (m *mockSignalHandler) HandleAnswer(from, to string, answer *webrtc.SessionDescription) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answerCount++
}

func (m *mockSignalHandler) HandleCandidate(from, to string, candidate *webrtc.ICECandidateInit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.candidateCount++
}

// TestSignalingClientReconnect tests reconnection with backoff
func TestSignalingClientReconnect(t *testing.T) {
	var connectCount int
	var mu sync.Mutex

	// Mock WebSocket server that closes connections after accepting them
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connectCount++
		mu.Unlock()

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Immediately close to force reconnection
		conn.Close()
	}))
	defer server.Close()

	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	client := newSignalingClient(wsURL, t.Logf)
	handler := &mockSignalHandler{}
	err := client.Start(handler)
	if err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}
	defer client.Close()

	// Wait for a few reconnection attempts
	time.Sleep(3 * time.Second)

	mu.Lock()
	count := connectCount
	mu.Unlock()

	// Should have attempted to connect multiple times
	if count < 2 {
		t.Errorf("Expected multiple reconnection attempts, got %d", count)
	}

	t.Logf("Reconnected %d times", count)
}

// TestWebRTCMagicIP tests the WebRTC magic IP constant
func TestWebRTCMagicIP(t *testing.T) {
	if tailcfg.WebRTCMagicIPAddr.String() != "127.3.3.41" {
		t.Errorf("WebRTC magic IP = %v, want 127.3.3.41", tailcfg.WebRTCMagicIPAddr)
	}

	// Verify it's different from DERP magic IP
	if tailcfg.WebRTCMagicIPAddr == tailcfg.DerpMagicIPAddr {
		t.Error("WebRTC magic IP should be different from DERP magic IP")
	}
}

// TestWebRTCPathPriority tests path preference logic
func TestWebRTCPathPriority(t *testing.T) {
	directV4 := addrQuality{
		epAddr: epAddr{
			ap: netip.MustParseAddrPort("192.168.1.100:41641"),
		},
		latency: 10 * time.Millisecond,
	}

	webrtc := addrQuality{
		epAddr: epAddr{
			ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, 12345),
		},
		latency: 50 * time.Millisecond,
	}

	derp := addrQuality{
		epAddr: epAddr{
			ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1),
		},
		latency: 100 * time.Millisecond,
	}

	tests := []struct {
		name string
		a, b addrQuality
		want bool // true if a is better than b
	}{
		{
			name: "direct beats WebRTC",
			a:    directV4,
			b:    webrtc,
			want: true,
		},
		{
			name: "WebRTC beats DERP",
			a:    webrtc,
			b:    derp,
			want: true,
		},
		{
			name: "direct beats DERP",
			a:    directV4,
			b:    derp,
			want: true,
		},
		{
			name: "DERP loses to WebRTC",
			a:    derp,
			b:    webrtc,
			want: false,
		},
		{
			name: "WebRTC loses to direct",
			a:    webrtc,
			b:    directV4,
			want: false,
		},
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

// TestWebRTCReadResult tests webrtcReadResult structure
func TestWebRTCReadResult(t *testing.T) {
	nodeKey := key.NewNode()
	testData := []byte("test packet data")

	result := webrtcReadResult{
		n:   len(testData),
		src: nodeKey.Public(),
		copyBuf: func(dst []byte) int {
			return copy(dst, testData)
		},
	}

	// Test copyBuf
	buf := make([]byte, 100)
	n := result.copyBuf(buf)
	if n != len(testData) {
		t.Errorf("copyBuf returned %d, want %d", n, len(testData))
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("copyBuf data = %q, want %q", buf[:n], testData)
	}

	// Test fields
	if result.n != len(testData) {
		t.Errorf("result.n = %d, want %d", result.n, len(testData))
	}
	if result.src != nodeKey.Public() {
		t.Errorf("result.src mismatch")
	}
}

// TestDiscoRXPathWebRTC tests the WebRTC disco path constant
func TestDiscoRXPathWebRTC(t *testing.T) {
	if discoRXPathWebRTC != "WebRTC" {
		t.Errorf("discoRXPathWebRTC = %q, want %q", discoRXPathWebRTC, "WebRTC")
	}

	// Verify it's different from other paths
	if discoRXPathWebRTC == discoRXPathDERP {
		t.Error("WebRTC path should be different from DERP path")
	}
	if discoRXPathWebRTC == discoRXPathUDP {
		t.Error("WebRTC path should be different from UDP path")
	}
}

// TestWebRTCMetrics tests that WebRTC metrics are properly defined
func TestWebRTCMetrics(t *testing.T) {
	// Test that metric variables exist (they're package-level variables)
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

	t.Log("WebRTC metrics are properly defined")
}

// TestPathWebRTCConstant tests the PathWebRTC constant
func TestPathWebRTCConstant(t *testing.T) {
	if PathWebRTC != "webrtc" {
		t.Errorf("PathWebRTC = %q, want %q", PathWebRTC, "webrtc")
	}

	// Verify it's different from other paths
	if PathWebRTC == PathDERP {
		t.Error("PathWebRTC should be different from PathDERP")
	}
	if PathWebRTC == PathDirectIPv4 {
		t.Error("PathWebRTC should be different from PathDirectIPv4")
	}
}
