// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package certs implements logic to help multiple Kubernetes replicas share TLS
// certs for a common Tailscale Service.
package certs

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"

	"tailscale.com/client/local"
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
		// L7 Web handlers (HA Ingress).
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
		// L4 TCP handlers with TLS termination (kube-apiserver proxy).
		for _, handler := range service.TCP {
			if handler != nil && handler.TerminateTLS != "" {
				currentDomains[handler.TerminateTLS] = true
			}
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

// Shutdown cancels all running cert loops and blocks until they exit, or
// until ctx is done.
func (cm *CertManager) Shutdown(ctx context.Context) error {
	cm.mu.Lock()
	for d, cancel := range cm.certLoops {
		cancel()
		delete(cm.certLoops, d)
	}
	cm.mu.Unlock()

	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if cm.tracker.RunningGoroutines() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// isTransientCertErr reports whether err represents a failure that did not
// reach the CA (ctx timeout, LocalAPI socket unreachable). Such errors must
// not advance the loop's retryCount.
func isTransientCertErr(err error) bool {
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.EPIPE):
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// retrySchedule is the wait between successive failed issuance attempts.
// It follows the schedule that Let's Encrypt's rate-limit adjustment guidance
// recommends ("1 minute, then 10 minutes, then 100 minutes, then once per
// day"). Anything more aggressive burns attempts inside the same 168h window
// during a genuine rate-limit event without improving recovery time.
// https://letsencrypt.org/docs/integration-guide/#retrying-failures
var retrySchedule = []time.Duration{
	1 * time.Minute,
	10 * time.Minute,
	100 * time.Minute,
	24 * time.Hour,
}

// runCertLoop:
// - calls localAPI certificate endpoint to ensure that certs are issued for the
// given domain name
// - calls localAPI certificate endpoint daily to ensure that certs are renewed
// - if certificate issuance failed, retries on the schedule defined by
// [retrySchedule]; resets to the start once issuance succeeds.
// Note that renewal check also happens when the node receives an HTTPS request and it is possible that certs get
// renewed at that point. Renewal here is needed to prevent the shared certs from expiry in edge cases where the 'write'
// replica does not get any HTTPS requests.
func (cm *CertManager) runCertLoop(ctx context.Context, domain string) {
	const normalInterval = 24 * time.Hour // regular renewal check

	if err := cm.waitForCertDomain(ctx, domain); err != nil {
		// Best-effort, log and continue with the issuing loop.
		cm.logf("error waiting for cert domain %s: %v", domain, err)
	}

	// Stagger initial fire so that when several domains come online at
	// once we don't stampede tailscaled's shared cert mutex.
	timer := time.NewTimer(mathrand.N(initialJitter))
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
			//
			// The 30m timeout below is a wedge detector, not a bound on ACME
			// work. All issuances on a write replica serialise through a
			// single mutex inside tailscaled, so this call must allow for both
			// queue-wait and the ACME flow itself. Realistic ACME work is
			// ~30s-2min per call; 30m comfortably covers queue contention from
			// ~15 domains ahead of us. Values below ~15m cause spurious
			// failures under realistic queue contention and drive the schedule
			// above into backoff for loops that never reached the CA. If this
			// timeout ever fires it is genuine evidence that something is
			// stuck (deadlock, leaked lock, wedged socket), not slow.
			ctxT, cancel := context.WithTimeout(ctx, 30*time.Minute)
			_, _, err := cm.lc.CertPair(ctxT, domain)
			cancel()
			var nextInterval time.Duration
			switch {
			case err == nil:
				retryCount = 0
				nextInterval = normalInterval
			case isTransientCertErr(err):
				// Never reached the CA. Don't escalate.
				nextInterval = retrySchedule[0]
			default:
				retryCount++
				idx := retryCount - 1
				if idx >= len(retrySchedule) {
					idx = len(retrySchedule) - 1
				}
				nextInterval = retrySchedule[idx]
				// CA-supplied Retry-After overrides the local schedule;
				// retryCount still advances.
				var rle *local.RateLimitedError
				if errors.As(err, &rle) && rle.RetryAfter > 0 {
					nextInterval = rle.RetryAfter
				}
			}
			if err != nil {
				cm.logf("Error refreshing certificate for %s (retry %d): %v. Will retry in %v\n",
					domain, retryCount, err, nextInterval)
			}
			timer.Reset(nextInterval)
		}
	}
}

// waitForCertDomainHeartbeat is how often waitForCertDomain logs while still
// waiting. var (not const) so tests can shorten it.
var waitForCertDomainHeartbeat = 5 * time.Minute

// initialJitter is the max random delay before a cert loop's first CertPair
// call. Spreads startup load across the shared cert mutex in tailscaled.
// var (not const) so tests can shorten it.
var initialJitter = 60 * time.Second

// domains before issuing the cert for the first time. It uses the IPN bus
// only as a wake-up trigger (Notify.SelfChange) and queries the current
// cert domains explicitly via [LocalClient.CertDomains].
func (cm *CertManager) waitForCertDomain(ctx context.Context, domain string) error {
	w, err := cm.lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return fmt.Errorf("error watching IPN bus: %w", err)
	}
	defer w.Close()

	// Pump w.Next() through a channel so we can interleave with a
	// heartbeat ticker. Closing w (via defer above on ctx cancel) is what
	// unblocks Next.
	type wake struct {
		hasSelfChange bool
		err           error
	}
	wakes := make(chan wake, 1)
	go func() {
		for {
			n, err := w.Next()
			if err != nil {
				select {
				case wakes <- wake{err: err}:
				case <-ctx.Done():
				}
				return
			}
			if n.SelfChange == nil {
				continue
			}
			select {
			case wakes <- wake{hasSelfChange: true}:
			case <-ctx.Done():
				return
			}
		}
	}()

	heartbeat := time.NewTicker(waitForCertDomainHeartbeat)
	defer heartbeat.Stop()
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			cm.logf("cert: still waiting for domain %s in netmap (%v elapsed)",
				domain, time.Since(start).Round(time.Second))
		case wk := <-wakes:
			if wk.err != nil {
				return wk.err
			}
			domains, err := cm.lc.CertDomains(ctx)
			if err != nil {
				continue
			}
			if slices.Contains(domains, domain) {
				return nil
			}
		}
	}
}
