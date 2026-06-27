// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"context"
	"net"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/set"
)

// certRefreshInterval is how often the background loop iterates the set
// of applicable cert domains and pokes the renewal machinery. The loop
// is only started while there's at least one HTTPS Web entry in the
// ServeConfig, so this cadence doesn't tick on idle/mobile nodes.
const certRefreshInterval = time.Hour

// updateCertRefreshLoop starts or stops the background TLS cert refresh
// loop based on whether the backend currently has any HTTPS-serving
// hostname whose cert should be kept fresh. The loop runs only while:
//
//   - the node is in [ipn.Running], and
//   - the current [ipn.ServeConfig] has at least one HTTPS-serving entry.
//
// We deliberately don't keep an idle timer around on hosts that have no
// certs to maintain (e.g. mobile devices that never run Serve), so this
// is called whenever any of those inputs change: state transitions and
// ServeConfig reloads. The caller (in [ipn/ipnlocal]) holds b.mu when
// invoking this; we use our own e.mu for the refresh-loop bookkeeping.
func (e *Extension) updateCertRefreshLoop(b *ipnlocal.LocalBackend, state ipn.State, sc ipn.ServeConfigView) {
	shouldRun := state == ipn.Running && serveConfigUsesACMECerts(sc)

	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case shouldRun && e.certRefreshCancel == nil:
		ctx, cancel := context.WithCancel(context.Background())
		e.certRefreshCancel = cancel
		b.Go(func() { e.certRefreshLoop(b, ctx) })
	case !shouldRun && e.certRefreshCancel != nil:
		e.certRefreshCancel()
		e.certRefreshCancel = nil
	}
}

// certRefreshLoop periodically iterates the domains configured for
// Serve or Funnel HTTPS and calls GetCertPEM on each. The existing
// renewal machinery in getCertPEM decides whether anything needs to
// happen (ARI check or expiry-based fallback); the loop just ensures
// it runs even on nodes that see no inbound TLS traffic.
//
// The first iteration runs immediately so that a node coming back
// online with stale or absent certs starts ACME within seconds rather
// than waiting a full interval.
func (e *Extension) certRefreshLoop(b *ipnlocal.LocalBackend, ctx context.Context) {
	if envknob.IsCertShareReadOnlyMode() {
		b.Logger()("cert refresh loop: cert-share read-only mode; loop is a no-op")
		return
	}

	e.refreshApplicableCerts(b, ctx)

	ticker, tickerCh := b.Clock().NewTicker(certRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tickerCh:
			e.refreshApplicableCerts(b, ctx)
		case <-ctx.Done():
			return
		}
	}
}

// refreshApplicableCerts is one iteration of the cert refresh loop.
//
// It enumerates the Serve/Funnel-configured HTTPS hostnames, keeps
// those that resolveCertDomain accepts (CertDomain, wildcard, or BYO
// Funnel domain), and calls [LocalBackend.GetCertPEM] for each. The
// renewal decision is delegated to the existing logic in getCertPEM.
func (e *Extension) refreshApplicableCerts(b *ipnlocal.LocalBackend, ctx context.Context) {
	sc := b.ServeConfig()
	if !sc.Valid() {
		return
	}

	want := set.Set[string]{}
	consider := func(host string) {
		if host == "" {
			return
		}
		if _, err := e.resolveCertDomain(b, host); err != nil {
			return
		}
		want.Add(host)
	}
	for hp := range sc.Webs() {
		host, _, err := net.SplitHostPort(string(hp))
		if err != nil {
			continue
		}
		consider(host)
	}
	for _, tcp := range sc.TCPs() {
		consider(tcp.TerminateTLS())
	}
	for _, svc := range sc.Services().All() {
		for _, tcp := range svc.TCP().All() {
			consider(tcp.TerminateTLS())
		}
	}
	if want.Len() == 0 {
		return
	}

	for d := range want {
		b.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if _, err := b.GetCertPEM(ctx, d); err != nil {
				b.Logger()("cert refresh: %s: %v", d, err)
			}
		})
	}
}

// serveConfigUsesACMECerts reports whether sc has any entry that
// causes tailscaled to obtain ACME-managed TLS certs: an HTTPS Web
// entry (background, foreground, or service) or a TCP handler with
// TerminateTLS set (`tailscale serve --tls-terminated-tcp`).
func serveConfigUsesACMECerts(sc ipn.ServeConfigView) bool {
	if !sc.Valid() {
		return false
	}
	for range sc.Webs() {
		return true
	}
	for _, tcp := range sc.TCPs() {
		if tcp.TerminateTLS() != "" {
			return true
		}
	}
	for _, svc := range sc.Services().All() {
		for _, tcp := range svc.TCP().All() {
			if tcp.TerminateTLS() != "" {
				return true
			}
		}
	}
	return false
}
