// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailperf registers Tailperf PeerAPI handlers.
package tailperf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	core "tailscale.com/tailperf"
)

func init() {
	feature.Register("tailperf")
	ipnlocal.RegisterPeerAPIHandler("/v0/tailperf/start", handlePeerAPIStart)
	ipnlocal.RegisterPeerAPIHandler("/v0/tailperf/status", handlePeerAPIStatus)
}

type startRequest struct {
	Protocol       core.Protocol `json:"protocol"`
	DurationMillis int64         `json:"durationMillis"`
	Port           uint16        `json:"port,omitempty"`
	NoTUN          bool          `json:"noTun,omitempty"`
	NoLog          bool          `json:"noLog,omitempty"`
}

type startResponse struct {
	Port      uint16    `json:"port"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type statusResponse struct {
	Busy  bool                      `json:"busy"`
	Rules []tailcfg.TailperfCapRule `json:"rules,omitempty"`
}

var defaultManager manager

type manager struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	starting bool
}

type boundServer struct {
	serve func(context.Context) error
	close func() error
}

var errBusy = errors.New("another performance test is already running")

var tailperfCapabilityNames = []tailcfg.PeerCapability{
	tailcfg.PeerCapabilityTailperf,
	tailcfg.PeerCapabilityTailperfLegacy,
}

func (m *manager) Start(ctx context.Context, cfg core.ServerConfig, maxAge time.Duration) (time.Time, error) {
	cfg, err := core.NormalizeServerConfig(cfg)
	if err != nil {
		return time.Time{}, err
	}
	if maxAge <= 0 || maxAge > core.MaxDuration+10*time.Second {
		return time.Time{}, fmt.Errorf("invalid tailperf listener lifetime")
	}
	m.mu.Lock()
	if m.cancel != nil || m.starting {
		m.mu.Unlock()
		return time.Time{}, errBusy
	}
	m.starting = true
	m.mu.Unlock()

	srv, err := listenServer(cfg)
	m.mu.Lock()
	m.starting = false
	if err != nil {
		m.mu.Unlock()
		return time.Time{}, err
	}
	if m.cancel != nil {
		m.mu.Unlock()
		_ = srv.close()
		return time.Time{}, errBusy
	}
	runCtx, cancel := context.WithTimeout(context.Background(), maxAge)
	m.cancel = cancel
	m.mu.Unlock()

	expires := time.Now().Add(maxAge)
	go func() {
		defer func() {
			m.mu.Lock()
			m.cancel = nil
			m.mu.Unlock()
			cancel()
		}()
		_ = srv.serve(runCtx)
	}()
	return expires, nil
}

func (m *manager) Busy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cancel != nil || m.starting
}

func listenServer(cfg core.ServerConfig) (boundServer, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port)
	switch cfg.Protocol {
	case core.ProtoTCP:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return boundServer{}, err
		}
		return boundServer{
			serve: func(ctx context.Context) error { return core.ServeTCP(ctx, ln) },
			close: ln.Close,
		}, nil
	case core.ProtoUDP:
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return boundServer{}, err
		}
		return boundServer{
			serve: func(ctx context.Context) error { return core.ServeUDP(ctx, pc) },
			close: pc.Close,
		}, nil
	default:
		return boundServer{}, fmt.Errorf("unsupported tailperf protocol %q", cfg.Protocol)
	}
}

func handlePeerAPIStatus(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	handlePeerAPIStatusWithManager(h, w, r, &defaultManager)
}

func handlePeerAPIStatusWithManager(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request, m *manager) {
	if r.Method != "GET" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	rules, ok := peerAPITailperfRules(h, w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statusResponse{
		Busy:  m.Busy(),
		Rules: rules,
	})
}

func handlePeerAPIStart(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	rules, ok := peerAPITailperfRules(h, w)
	if !ok {
		return
	}
	var req startRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad tailperf request", http.StatusBadRequest)
		return
	}
	if req.Protocol == "" {
		req.Protocol = core.ProtoTCP
	}
	if !req.Protocol.Valid() {
		http.Error(w, "bad tailperf protocol", http.StatusBadRequest)
		return
	}
	duration := time.Duration(req.DurationMillis) * time.Millisecond
	if duration <= 0 || duration > core.MaxDuration {
		http.Error(w, "bad tailperf duration", http.StatusBadRequest)
		return
	}
	port, ok := allowedPort(rules, req.NoTUN, req.Port)
	if !ok {
		http.Error(w, "Tailperf denied: no configured listen port for this test mode.", http.StatusForbidden)
		return
	}
	expires, err := defaultManager.Start(r.Context(), core.ServerConfig{
		Port:     port,
		Protocol: req.Protocol,
	}, duration+10*time.Second)
	if errors.Is(err, errBusy) {
		http.Error(w, "Tailperf target is busy: another performance test is already running.", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Tailperf listener start failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(startResponse{Port: port, ExpiresAt: expires})
}

func peerAPITailperfRules(h ipnlocal.PeerAPIHandler, w http.ResponseWriter) ([]tailcfg.TailperfCapRule, bool) {
	if h.Peer().UnsignedPeerAPIOnly() {
		http.Error(w, "Tailperf denied: unsigned PeerAPI clients are not allowed.", http.StatusForbidden)
		return nil, false
	}
	rules, err := tailperfCapRules(h.PeerCaps())
	if err != nil {
		http.Error(w, "Tailperf denied: invalid tailscale.io/cap/tailperf grant.", http.StatusForbidden)
		return nil, false
	}
	if len(rules) == 0 {
		http.Error(w, "Tailperf denied: this user or node is not granted tailscale.io/cap/tailperf for the target.", http.StatusForbidden)
		return nil, false
	}
	return rules, true
}

func tailperfCapRules(caps tailcfg.PeerCapMap) ([]tailcfg.TailperfCapRule, error) {
	var rules []tailcfg.TailperfCapRule
	for _, capName := range tailperfCapabilityNames {
		rs, err := tailcfg.UnmarshalCapJSON[tailcfg.TailperfCapRule](caps, capName)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rs...)
	}
	return rules, nil
}

func allowedPort(rules []tailcfg.TailperfCapRule, noTUN bool, requested uint16) (uint16, bool) {
	for _, rule := range rules {
		port := rule.TUNListenPort
		if noTUN {
			port = rule.UserspaceListenPort
		}
		if port == 0 {
			continue
		}
		if requested != 0 && requested != port {
			continue
		}
		return port, true
	}
	return 0, false
}
