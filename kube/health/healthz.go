// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package health contains shared types and underlying methods for serving
// a `/healthz` endpoint for containerboot and k8s-proxy.
package health

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/logger"
)

// Healthz is a simple health check server. If enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address and the
// backend reports no connectivity-impacting health warnings, else 503.
type Healthz struct {
	sync.Mutex
	hasAddrs    bool
	badWarnings map[health.WarnableCode]string
	podIPv4     string
	logger      logger.Logf
}

func (h *Healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Lock()
	defer h.Unlock()

	if !h.hasAddrs {
		http.Error(w, "node currently has no tailscale IPs", http.StatusServiceUnavailable)
		return
	}
	if len(h.badWarnings) != 0 {
		http.Error(w, fmt.Sprintf("node is unhealthy: %s", h.warningsString()), http.StatusServiceUnavailable)
		return
	}

	w.Header().Add(kubetypes.PodIPv4Header, h.podIPv4)
	if _, err := w.Write([]byte("ok")); err != nil {
		http.Error(w, fmt.Sprintf("error writing status: %v", err), http.StatusInternalServerError)
	}
}

// warningsString summarizes the active connectivity-impacting warnings. The
// Mutex must be held.
func (h *Healthz) warningsString() string {
	msgs := make([]string, 0, len(h.badWarnings))
	for code, text := range h.badWarnings {
		msgs = append(msgs, fmt.Sprintf("%s: %s", code, text))
	}
	sort.Strings(msgs)
	return strings.Join(msgs, "; ")
}

func (h *Healthz) Update(healthy bool) {
	h.Lock()
	defer h.Unlock()

	if h.hasAddrs != healthy {
		h.logger("Setting healthy %v", healthy)
	}
	h.hasAddrs = healthy
}

// SetHealthState records the connectivity-impacting warnings from s so that
// ServeHTTP can fail the check while any are active. Callers that drive the
// health check from their own IPN bus watch loop (e.g. containerboot) call
// this directly instead of using MonitorHealth.
func (h *Healthz) SetHealthState(s *health.State) {
	bad := make(map[health.WarnableCode]string)
	if s != nil {
		for code, w := range s.Warnings {
			if w.ImpactsConnectivity {
				bad[code] = w.Text
			}
		}
	}

	h.Lock()
	defer h.Unlock()
	if !maps.Equal(bad, h.badWarnings) {
		h.logger("Setting %d connectivity-impacting health warning(s)", len(bad))
		h.badWarnings = bad
	}
}

func (h *Healthz) MonitorHealth(ctx context.Context, lc *local.Client) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap|ipn.NotifyInitialHealthState)
	if err != nil {
		return fmt.Errorf("failed to watch IPN bus: %w", err)
	}

	for {
		n, err := w.Next()
		if err != nil {
			return err
		}

		if self := n.SelfChange; self != nil {
			h.Update(len(self.Addresses) != 0)
		}
		if n.Health != nil {
			h.SetHealthState(n.Health)
		}
	}
}

// RegisterHealthHandlers registers a health handler at /healthz. A containerized
// tailscale instance is considered healthy if it has at least one tailnet IP
// address and reports no connectivity-impacting health warnings (see
// [health.Warnable.ImpactsConnectivity]).
func RegisterHealthHandlers(mux *http.ServeMux, podIPv4 string, logger logger.Logf) *Healthz {
	h := &Healthz{
		podIPv4: podIPv4,
		logger:  logger,
	}
	mux.Handle("GET /healthz", h)
	return h
}
