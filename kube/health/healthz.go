// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package health contains shared types and underlying methods for serving
// a `/healthz` endpoint for containerboot and k8s-proxy.
package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/logger"
)

// Healthz is a simple health check server, if enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address else
// returns 503.
type Healthz struct {
	sync.Mutex
	hasAddrs bool
	podIPv4  string
	logger   logger.Logf
}

func (h *Healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Lock()
	defer h.Unlock()

	if h.hasAddrs {
		w.Header().Add(kubetypes.PodIPv4Header, h.podIPv4)
		if _, err := w.Write([]byte("ok")); err != nil {
			http.Error(w, fmt.Sprintf("error writing status: %v", err), http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "node currently has no tailscale IPs", http.StatusServiceUnavailable)
	}
}

func (h *Healthz) Update(healthy bool) {
	h.Lock()
	defer h.Unlock()

	if h.hasAddrs != healthy {
		h.logger("Setting healthy %v", healthy)
	}
	h.hasAddrs = healthy
}

func (h *Healthz) MonitorHealth(ctx context.Context, lc *local.Client) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return fmt.Errorf("failed to watch IPN bus: %w", err)
	}

	for {
		n, err := w.Next()
		if err != nil {
			return err
		}

		if n.NetMap != nil {
			h.Update(n.NetMap.SelfNode.Addresses().Len() != 0)
		}
	}
}

// RegisterHealthHandlers registers a simple health handler at /healthz.
// A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func RegisterHealthHandlers(mux *http.ServeMux, podIPv4 string, logger logger.Logf) *Healthz {
	h := &Healthz{
		podIPv4: podIPv4,
		logger:  logger,
	}
	mux.Handle("GET /healthz", h)
	return h
}
