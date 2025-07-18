// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package health contains shared types and underlying methods for serving
// a `/healthz` endpoint to containerboot and k8s-proxy. This is primarily
// consumed by containerboot and k8s-proxy.
package health

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
)

// Healthz is a simple health check server, if enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address else
// returns 503.
type Healthz struct {
	sync.Mutex
	hasAddrs bool
	podIPv4  string
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
		log.Println("Setting healthy", healthy)
	}
	h.hasAddrs = healthy
}

func (h *Healthz) MonitorHealth(ctx context.Context, lc *local.Client) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return fmt.Errorf("rewatching tailscaled for updates after auth: %w", err)
	}

	for {
		n, err := w.Next()
		if err != nil {
			return err
		}

		if n.NetMap != nil {
			addrs := n.NetMap.SelfNode.Addresses().AsSlice()
			if len(addrs) > 0 {
				h.Update(true)
			}
			if len(addrs) < 1 {
				h.Update(false)
			}
		}
	}
}

// RegisterHealthHandlers registers a simple health handler at /healthz.
// A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func RegisterHealthHandlers(mux *http.ServeMux, podIPv4 string) *Healthz {
	h := &Healthz{podIPv4: podIPv4}
	mux.Handle("GET /healthz", h)
	return h
}
