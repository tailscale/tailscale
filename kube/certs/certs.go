// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package certs implements logic to help multiple Kubernetes replicas share TLS
// certs for a common Tailscale Service.
package certs

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/kube/localclient"
	"tailscale.com/types/logger"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/mak"
)

// CertManager is responsible for issuing certificates for known domains and for
// maintaining a loop that re-attempts issuance daily.
// Currently cert manager logic is only run on ingress ProxyGroup replicas that are responsible for managing certs for
// HA Ingress HTTPS endpoints ('write' replicas).
type CertManager struct {
	lc      localclient.LocalClient
	logf    logger.Logf
	tracker goroutines.Tracker // tracks running goroutines
	mu      sync.Mutex         // guards the following
	// certLoops contains a map of DNS names, for which we currently need to
	// manage certs to cancel functions that allow stopping a goroutine when
	// we no longer need to manage certs for the DNS name.
	certLoops map[string]context.CancelFunc
}

func NewCertManager(lc localclient.LocalClient, logf logger.Logf) *CertManager {
	return &CertManager{
		lc:   lc,
		logf: logf,
	}
}

// EnsureCertLoops ensures that, for all currently managed Service HTTPS
// endpoints, there is a cert loop responsible for issuing and ensuring the
// renewal of the TLS certs.
// ServeConfig must not be nil.
func (cm *CertManager) EnsureCertLoops(ctx context.Context, sc *ipn.ServeConfig) error {
	if sc == nil {
		return fmt.Errorf("[unexpected] ensureCertLoops called with nil ServeConfig")
	}
	currentDomains := make(map[string]bool)
	const httpsPort = "443"
	for _, service := range sc.Services {
		for hostPort := range service.Web {
			domain, port, err := net.SplitHostPort(string(hostPort))
			if err != nil {
				return fmt.Errorf("[unexpected] unable to parse HostPort %s", hostPort)
			}
			if port != httpsPort { // HA Ingress' HTTP endpoint
				continue
			}
			currentDomains[domain] = true
		}
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for domain := range currentDomains {
		if _, exists := cm.certLoops[domain]; !exists {
			cancelCtx, cancel := context.WithCancel(ctx)
			mak.Set(&cm.certLoops, domain, cancel)
			// Note that most of the issuance anyway happens
			// serially because the cert client has a shared lock
			// that's held during any issuance.
			cm.tracker.Go(func() { cm.runCertLoop(cancelCtx, domain) })
		}
	}

	// Stop goroutines for domain names that are no longer in the config.
	for domain, cancel := range cm.certLoops {
		if !currentDomains[domain] {
			cancel()
			delete(cm.certLoops, domain)
		}
	}
	return nil
}

// runCertLoop:
// - calls localAPI certificate endpoint to ensure that certs are issued for the
// given domain name
// - calls localAPI certificate endpoint daily to ensure that certs are renewed
// - if certificate issuance failed retries after an exponential backoff period
// starting at 1 minute and capped at 24 hours. Reset the backoff once issuance succeeds.
// Note that renewal check also happens when the node receives an HTTPS request and it is possible that certs get
// renewed at that point. Renewal here is needed to prevent the shared certs from expiry in edge cases where the 'write'
// replica does not get any HTTPS requests.
// https://letsencrypt.org/docs/integration-guide/#retrying-failures
func (cm *CertManager) runCertLoop(ctx context.Context, domain string) {
	const (
		normalInterval   = 24 * time.Hour  // regular renewal check
		initialRetry     = 1 * time.Minute // initial backoff after a failure
		maxRetryInterval = 24 * time.Hour  // max backoff period
	)

	if err := cm.waitForCertDomain(ctx, domain); err != nil {
		// Best-effort, log and continue with the issuing loop.
		cm.logf("error waiting for cert domain %s: %v", domain, err)
	}

	timer := time.NewTimer(0) // fire off timer immediately
	defer timer.Stop()
	retryCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// We call the certificate endpoint, but don't do anything with the
			// returned certs here. The call to the certificate endpoint will
			// ensure that certs are issued/renewed as needed and stored in the
			// relevant state store. For example, for HA Ingress 'write' replica,
			// the cert and key will be stored in a Kubernetes Secret named after
			// the domain for which we are issuing.
			//
			// Note that renewals triggered by the call to the certificates
			// endpoint here and by renewal check triggered during a call to
			// node's HTTPS endpoint share the same state/renewal lock mechanism,
			// so we should not run into redundant issuances during concurrent
			// renewal checks.

			// An issuance holds a shared lock, so we need to avoid a situation
			// where other services cannot issue certs because a single one is
			// holding the lock.
			ctxT, cancel := context.WithTimeout(ctx, time.Second*300)
			_, _, err := cm.lc.CertPair(ctxT, domain)
			cancel()
			if err != nil {
				cm.logf("error refreshing certificate for %s: %v", domain, err)
			}
			var nextInterval time.Duration
			// TODO(irbekrm): distinguish between LE rate limit errors and other
			// error types like transient network errors.
			if err == nil {
				retryCount = 0
				nextInterval = normalInterval
			} else {
				retryCount++
				// Calculate backoff: initialRetry * 2^(retryCount-1)
				// For retryCount=1: 1min * 2^0 = 1min
				// For retryCount=2: 1min * 2^1 = 2min
				// For retryCount=3: 1min * 2^2 = 4min
				backoff := initialRetry * time.Duration(1<<(retryCount-1))
				if backoff > maxRetryInterval {
					backoff = maxRetryInterval
				}
				nextInterval = backoff
				cm.logf("Error refreshing certificate for %s (retry %d): %v. Will retry in %v\n",
					domain, retryCount, err, nextInterval)
			}
			timer.Reset(nextInterval)
		}
	}
}

// waitForCertDomain ensures the requested domain is in the list of allowed
// domains before issuing the cert for the first time.
func (cm *CertManager) waitForCertDomain(ctx context.Context, domain string) error {
	w, err := cm.lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return fmt.Errorf("error watching IPN bus: %w", err)
	}
	defer w.Close()

	for {
		n, err := w.Next()
		if err != nil {
			return err
		}
		if n.NetMap == nil {
			continue
		}

		if slices.Contains(n.NetMap.DNS.CertDomains, domain) {
			return nil
		}
	}
}
