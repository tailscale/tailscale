// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package tailnetdns tracks the tailnet's split DNS configuration, as seen by
// the operator's own Tailscale device, and notifies controllers when it
// changes.
package tailnetdns

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
)

const (
	// DefaultInterval is how often the tailnet's DNS configuration is polled
	// once it has been read successfully. The local API has no way to watch
	// it for changes.
	DefaultInterval = 30 * time.Second

	// startupInterval is how often the DNS configuration is polled until it
	// has been read successfully, which fails until the operator's device has
	// received its first netmap.
	startupInterval = 5 * time.Second
)

// Change is the payload of the events a Watcher emits. It carries no data:
// consumers read the current routes from the Watcher.
type Change struct{}

// DNSConfigGetter returns the current DNS configuration of a Tailscale device.
// It is implemented by *local.Client.
type DNSConfigGetter interface {
	DNSConfig(ctx context.Context) (*tailcfg.DNSConfig, error)
}

// Source is what controllers consume: the current split DNS routes and a
// channel that delivers an event whenever they change.
type Source interface {
	// Routes returns the tailnet's split DNS routes: domain (without trailing
	// dot) to the addresses of the nameservers for it, in order of preference.
	Routes() map[string][]netip.AddrPort
	// Events delivers an event whenever the result of Routes changes.
	Events() <-chan event.TypedGenericEvent[Change]
}

// Watcher polls a device's DNS configuration and implements Source. It is a
// manager.Runnable.
type Watcher struct {
	getter   DNSConfigGetter
	interval time.Duration
	logger   *zap.SugaredLogger
	events   chan event.TypedGenericEvent[Change]

	mu      sync.Mutex
	fetched bool
	routes  map[string][]netip.AddrPort
}

// New returns a Watcher polling getter every DefaultInterval.
func New(getter DNSConfigGetter, logger *zap.SugaredLogger) *Watcher {
	return NewWithInterval(getter, logger, DefaultInterval)
}

// NewWithInterval returns a Watcher polling getter every interval.
func NewWithInterval(getter DNSConfigGetter, logger *zap.SugaredLogger, interval time.Duration) *Watcher {
	return &Watcher{
		getter:   getter,
		interval: interval,
		logger:   logger.Named("tailnetdns"),
		// Events are coalesced: a single pending event is enough, as
		// consumers read the current routes when they handle it.
		events: make(chan event.TypedGenericEvent[Change], 1),
	}
}

// Start polls until ctx is done. It never returns an error: a device without
// a netmap yet is retried.
func (w *Watcher) Start(ctx context.Context) error {
	for {
		w.poll(ctx)
		interval := w.interval
		if !w.hasFetched() {
			interval = min(startupInterval, w.interval)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// NeedLeaderElection reports that only the elected operator instance should
// poll, as only it reconciles what the routes feed into.
func (w *Watcher) NeedLeaderElection() bool {
	return true
}

func (w *Watcher) hasFetched() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fetched
}

// poll reads the DNS configuration once and emits an event if the routes
// changed.
func (w *Watcher) poll(ctx context.Context) {
	cfg, err := w.getter.DNSConfig(ctx)
	if err != nil {
		w.logger.Debugf("failed to read the tailnet's DNS configuration, will retry: %v", err)
		return
	}
	routes := RoutesFromDNSConfig(cfg, w.logger)

	w.mu.Lock()
	changed := !w.fetched || !maps.EqualFunc(w.routes, routes, slices.Equal)
	w.routes = routes
	w.fetched = true
	w.mu.Unlock()

	if !changed {
		return
	}
	w.logger.Infof("tailnet split DNS routes changed: %v", routes)
	select {
	case w.events <- event.TypedGenericEvent[Change]{}:
	default:
	}
}

// Routes implements Source. It returns nil until the configuration has been
// read at least once.
func (w *Watcher) Routes() map[string][]netip.AddrPort {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.routes == nil {
		return nil
	}
	out := make(map[string][]netip.AddrPort, len(w.routes))
	for domain, addrs := range w.routes {
		out[domain] = slices.Clone(addrs)
	}
	return out
}

// Events implements Source.
func (w *Watcher) Events() <-chan event.TypedGenericEvent[Change] {
	return w.events
}

// RoutesFromDNSConfig extracts the split DNS routes that can be forwarded to
// from cfg: every route with at least one resolver that has a plain IP
// address. Routes without resolvers are handled by MagicDNS and skipped, as
// are resolvers using DNS-over-HTTPS or other transports. Domains are
// normalized to lower case without a trailing dot; nameserver addresses keep
// the tailnet's order of preference.
func RoutesFromDNSConfig(cfg *tailcfg.DNSConfig, logger *zap.SugaredLogger) map[string][]netip.AddrPort {
	if cfg == nil || len(cfg.Routes) == 0 {
		return map[string][]netip.AddrPort{}
	}
	routes := make(map[string][]netip.AddrPort, len(cfg.Routes))
	for domain, resolvers := range cfg.Routes {
		fqdn, err := dnsname.ToFQDN(domain)
		if err != nil {
			logger.Debugf("skipping split DNS route for invalid domain %q: %v", domain, err)
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(fqdn.WithoutTrailingDot()), ".")
		var addrs []netip.AddrPort
		for _, r := range resolvers {
			if r == nil {
				continue
			}
			ap, ok := r.IPPort()
			if !ok {
				logger.Debugf("skipping split DNS resolver %q for %q: only nameservers with plain IP addresses can be forwarded to", r.Addr, name)
				continue
			}
			addrs = append(addrs, ap)
		}
		if len(addrs) == 0 {
			continue
		}
		routes[name] = addrs
	}
	return routes
}
