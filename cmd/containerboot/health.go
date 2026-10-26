// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/kube/certs"
	healthz "tailscale.com/kube/health"
	"tailscale.com/tailcfg"
)

// Names of the checks served at /livez and /readyz.
const (
	// checkTailscaled is a liveness check that tailscaled answers LocalAPI
	// requests.
	checkTailscaled = "tailscaled"
	// checkNetmap is a readiness condition that this node has Tailscale IPs
	// and the proxy rules for them are installed.
	checkNetmap = "netmap"
	// checkServe is a readiness condition that the serve config file has been
	// applied.
	checkServe = "serve"
	// checkCerts is a readiness check that tailscaled's cert store holds a
	// TLS cert for each HTTPS-only Tailscale Service this node advertises.
	checkCerts = "certs"
)

// Reasons the checks give when failing.
const (
	reasonNoTailscaleIPs  = "node currently has no Tailscale IPs"
	reasonServeNotApplied = "serve config not yet applied"
	reasonCertsNotPresent = "TLS certs not yet present for all advertised Tailscale Services"
)

// healthLocalClient is the subset of [local.Client] used by the health checks.
type healthLocalClient interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
	GetPrefs(context.Context) (*ipn.Prefs, error)
	GetServeConfig(context.Context) (*ipn.ServeConfig, error)
}

// readinessConditions are the /readyz conditions set by the code that owns
// each piece of state. A condition is nil if this proxy doesn't register it.
type readinessConditions struct {
	netmap *healthz.Condition // set by the run loop on each netmap
	serve  *healthz.Condition // set by watchServeConfigChanges
}

// registerHealthChecks registers the /livez and /readyz probes and their
// checks on mux. It must be called before mux is served.
func registerHealthChecks(mux *http.ServeMux, cfg *settings, lc healthLocalClient, cm *certs.CertManager) readinessConditions {
	log.Printf("Running liveness and readiness endpoints at %s/livez and %s/readyz", cfg.LocalAddrPort, cfg.LocalAddrPort)
	lz := healthz.RegisterLivezHandlers(mux, log.Printf)
	lz.AddCheck(checkTailscaled, tailscaledResponding(lc))

	rz := healthz.RegisterReadyzHandlers(mux, log.Printf)
	var rc readinessConditions
	rc.netmap = rz.AddCondition(checkNetmap, reasonNoTailscaleIPs)
	if cfg.ServeConfigPath != "" {
		rc.serve = rz.AddCondition(checkServe, reasonServeNotApplied)
		rz.AddCheck(checkCerts, certsPresent(cm, lc))
	}
	return rc
}

// tailscaledResponding returns a check that passes if tailscaled answers a
// LocalAPI status request.
func tailscaledResponding(lc healthLocalClient) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := lc.StatusWithoutPeers(ctx); err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		return nil
	}
}

// certsPresent returns a check that passes if tailscaled's cert store holds a
// TLS cert for each HTTPS-only Tailscale Service in its serve config that this
// node advertises. The operator only advertises an HTTPS-only Tailscale Service
// once its cert has been issued, so one stuck on issuance doesn't fail every
// replica.
func certsPresent(cm *certs.CertManager, lc healthLocalClient) func(context.Context) error {
	return func(ctx context.Context) error {
		sc, err := lc.GetServeConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to get serve config: %w", err)
		}
		prefs, err := lc.GetPrefs(ctx)
		if err != nil {
			return fmt.Errorf("failed to get prefs: %w", err)
		}
		ok, err := cm.AllCertsPresent(ctx, advertisedServices(sc, prefs.AdvertiseServices))
		switch {
		case err != nil:
			return fmt.Errorf("failed to check TLS certs: %w", err)
		case !ok:
			return errors.New(reasonCertsNotPresent)
		}
		return nil
	}
}

// advertisedServices returns a copy of sc with only the Tailscale Services in
// advertised that don't also serve HTTP.
func advertisedServices(sc *ipn.ServeConfig, advertised []string) *ipn.ServeConfig {
	out := *sc
	out.Services = make(map[tailcfg.ServiceName]*ipn.ServiceConfig)
	for _, svc := range advertised {
		cfg, ok := sc.Services[tailcfg.ServiceName(svc)]
		if !ok {
			continue
		}
		// The operator advertises Services with an HTTP endpoint before their cert is issued.
		if h := cfg.TCP[80]; h != nil && h.HTTP {
			continue
		}
		out.Services[tailcfg.ServiceName(svc)] = cfg
	}
	return &out
}
