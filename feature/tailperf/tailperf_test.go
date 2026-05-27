// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	core "tailscale.com/tailperf"
)

func TestTailperfCapRules(t *testing.T) {
	caps := tailcfg.PeerCapMap{
		tailcfg.PeerCapability("tailscale.io/cap/tailperf"): []tailcfg.RawMessage{
			`{"tun_listen_port":22345}`,
		},
		tailcfg.PeerCapability("https://tailscale.com/cap/tailperf"): []tailcfg.RawMessage{
			`{"userspace_listen_port":12345}`,
		},
	}
	rules, err := tailperfCapRules(caps)
	if err != nil {
		t.Fatalf("tailperfCapRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if rules[0].TUNListenPort != 22345 {
		t.Fatalf("rules[0].TUNListenPort = %d, want 22345", rules[0].TUNListenPort)
	}
	if rules[1].UserspaceListenPort != 12345 {
		t.Fatalf("rules[1].UserspaceListenPort = %d, want 12345", rules[1].UserspaceListenPort)
	}
}

func TestAllowedPort(t *testing.T) {
	rules := []tailcfg.TailperfCapRule{{
		UserspaceListenPort: 12345,
		TUNListenPort:       22345,
	}}
	if got, ok := allowedPort(rules, false, 0); !ok || got != 22345 {
		t.Fatalf("TUN allowedPort = %d, %v; want 22345, true", got, ok)
	}
	if got, ok := allowedPort(rules, true, 12345); !ok || got != 12345 {
		t.Fatalf("userspace allowedPort = %d, %v; want 12345, true", got, ok)
	}
	if _, ok := allowedPort(rules, false, 12345); ok {
		t.Fatal("requested userspace port accepted for TUN mode")
	}
	if _, ok := allowedPort([]tailcfg.TailperfCapRule{{}}, false, 0); ok {
		t.Fatal("empty port config accepted")
	}
}

func TestHandlePeerAPIStatusReportsRulesAndBusy(t *testing.T) {
	var m manager
	m.mu.Lock()
	m.cancel = func() {}
	m.mu.Unlock()

	h := &peerAPIHandler{
		peerNode: (&tailcfg.Node{}).View(),
		caps: tailcfg.PeerCapMap{
			tailcfg.PeerCapabilityTailperf: []tailcfg.RawMessage{
				`{"tun_listen_port":22345,"userspace_listen_port":12345}`,
			},
		},
	}
	rr := httptest.NewRecorder()
	handlePeerAPIStatusWithManager(h, rr, httptest.NewRequest("GET", "/v0/tailperf/status", nil), &m)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var got statusResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Busy {
		t.Fatal("status Busy = false, want true")
	}
	if len(got.Rules) != 1 {
		t.Fatalf("len(status rules) = %d, want 1", len(got.Rules))
	}
	if got.Rules[0].TUNListenPort != 22345 || got.Rules[0].UserspaceListenPort != 12345 {
		t.Fatalf("status rules = %+v, want tun 22345 and userspace 12345", got.Rules[0])
	}
}

func TestHandlePeerAPIStatusRejectsUnauthorizedPeers(t *testing.T) {
	tests := []struct {
		name    string
		handler *peerAPIHandler
		want    string
	}{
		{
			name: "unsigned",
			handler: &peerAPIHandler{
				peerNode: (&tailcfg.Node{UnsignedPeerAPIOnly: true}).View(),
				caps: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityTailperf: []tailcfg.RawMessage{`{"tun_listen_port":22345}`},
				},
			},
			want: "unsigned PeerAPI clients are not allowed",
		},
		{
			name: "no grant",
			handler: &peerAPIHandler{
				peerNode: (&tailcfg.Node{}).View(),
			},
			want: "not granted tailscale.io/cap/tailperf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handlePeerAPIStatusWithManager(tt.handler, rr, httptest.NewRequest("GET", "/v0/tailperf/status", nil), &manager{})
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status code = %d, want %d; body: %s", rr.Code, http.StatusForbidden, rr.Body.String())
			}
			if body := rr.Body.String(); !strings.Contains(body, tt.want) {
				t.Fatalf("body = %q, want substring %q", body, tt.want)
			}
		})
	}
}

func TestManagerStartRejectsConcurrent(t *testing.T) {
	var m manager
	port := freeTCPPort(t)
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		Protocol: core.ProtoTCP,
	}, time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     freeTCPPort(t),
		Protocol: core.ProtoTCP,
	}, time.Second); !errors.Is(err, errBusy) {
		t.Fatalf("second Start error = %v, want errBusy", err)
	}
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := m.cancel == nil
		m.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("manager did not clean up after cancellation")
}

func TestManagerStartReportsListenFailure(t *testing.T) {
	var m manager
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		Protocol: core.ProtoTCP,
	}, time.Second); err == nil {
		t.Fatal("Start succeeded on an already-bound port")
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

type peerAPIHandler struct {
	peerNode tailcfg.NodeView
	caps     tailcfg.PeerCapMap
}

func (h *peerAPIHandler) Peer() tailcfg.NodeView               { return h.peerNode }
func (h *peerAPIHandler) PeerCaps() tailcfg.PeerCapMap         { return h.caps }
func (h *peerAPIHandler) CanDebug() bool                       { return false }
func (h *peerAPIHandler) Self() tailcfg.NodeView               { return (&tailcfg.Node{}).View() }
func (h *peerAPIHandler) LocalBackend() *ipnlocal.LocalBackend { panic("unexpected") }
func (h *peerAPIHandler) IsSelfUntagged() bool                 { return false }
func (h *peerAPIHandler) RemoteAddr() netip.AddrPort           { return netip.AddrPort{} }
func (h *peerAPIHandler) Logf(format string, a ...any)         {}
