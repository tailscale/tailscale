// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package acme registers the ACME/TLS-cert feature and implements its
// associated [ipnext.Extension]. The extension owns the per-LocalBackend
// ACME serialization mutex, in-flight cert tracking, the refresh loop's
// cancel func, and the test-only cert override; together with the cert
// acquisition logic in this package, it is everything tailscaled needs
// to obtain and renew TLS certificates via ACME.
//
// In builds without ACME support (js or ts_omit_acme), this package is
// not linked in; [ipn/ipnlocal] then exposes only stub wrappers that
// return errNoCerts or no-op.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/feature"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/syncs"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// featureName is the name of the feature implemented by this package.
const featureName = "acme"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)

	ipnlocal.HookGetCertPEM.Set(getCertPEMHook)
	ipnlocal.HookGetACMETLSALPNCert.Set(getACMETLSALPNCertHook)
	ipnlocal.HookGetACMETLSALPNProto.Set(getACMETLSALPNProtoHook)
	ipnlocal.HookUpdateCertRefreshLoop.Set(updateCertRefreshLoopHook)
	ipnlocal.HookShutdownCertRefreshLoop.Set(shutdownCertRefreshLoopHook)
	ipnlocal.HookConfigureCertsForTest.Set(configureCertsForTestHook)
	ipnlocal.HookHandleC2NTLSCertStatus.Set(handleC2NTLSCertStatus)
}

// errNoExt is returned when a hook is invoked on a [*ipnlocal.LocalBackend]
// that has no [extension] registered (shouldn't happen in practice, but
// guards against misuse from tests that swap extension registrations).
var errNoExt = errors.New("acme extension not registered on this LocalBackend")

// extension is the ACME/cert [ipnext.Extension]. It owns the
// per-[*ipnlocal.LocalBackend] state previously held in package-level
// globals and in [*ipnlocal.LocalBackend] fields.
//
// All methods that take a [*ipnlocal.LocalBackend] argument operate on
// the backend the extension was instantiated for; the argument is
// passed through from the hook in [ipn/ipnlocal] rather than stored on
// the extension, which keeps the extension's lifecycle independent of
// any specific backend reference.
type extension struct {
	logf logger.Logf

	// domainsMu guards domainLocks.
	domainsMu syncs.Mutex
	// domainLocks holds a per-domain mutex serialising ACME operations
	// for that domain. Different domains run concurrently; the same
	// domain still queues so the first goroutine fills the on-disk
	// cache and the rest reuse it. Entries are never removed; a node
	// only ever has a handful of domains so the map stays small.
	domainLocks map[string]*syncs.Mutex

	// accountMu serialises ACME account setup (key generation, LE
	// registration) so two first-time issuances don't create separate
	// accounts.
	accountMu syncs.Mutex

	// renewMu guards renewCertAt.
	// Lock order: per-domain lock before renewMu.
	renewMu     syncs.Mutex
	renewCertAt map[string]time.Time // lazily initialized under renewMu

	// pendingACMETLSALPNCerts maps SNI names to short-lived ACME
	// tls-alpn-01 challenge certificates while an ACME order is
	// waiting for validation. Entries are deleted by the cleanup
	// function returned from storeACMETLSALPNCert after the challenge
	// validation path finishes, whether it succeeds or fails.
	pendingACMETLSALPNCerts syncs.Map[string, *tls.Certificate]

	// pendingCertDomains tracks the set of domains for which an ACME
	// issuance is currently in flight with no usable cached cert. It
	// backs the tls-cert-pending health Warnable.
	// Guarded by pendingCertDomainsMu.
	pendingCertDomainsMu sync.Mutex
	pendingCertDomains   set.Set[string]

	// wg tracks all background goroutines spawned by this extension
	// (async cert renewals, the cert refresh loop and its per-domain
	// workers). [extension.Shutdown] waits on it.
	wg sync.WaitGroup

	// goroutinesStarted counts goroutines started via [extension.Go].
	// Tests use it to assert whether an operation kicked off async work.
	goroutinesStarted atomic.Int64

	// mu guards the test/lifecycle fields below.
	mu sync.Mutex

	// getCertForTest is used to retrieve TLS certificates in tests.
	// See [LocalBackend.ConfigureCertsForTest].
	getCertForTest func(hostname string) (*ipnlocal.TLSCertKeyPair, error)

	// certRefreshCancel cancels the background TLS cert refresh loop
	// that periodically pokes [LocalBackend.GetCertPEM] so renewals
	// happen on idle nodes. Non-nil while the loop is running.
	certRefreshCancel context.CancelFunc
}

// lockDomain returns the mutex for domain, creating it on first use.
func (e *extension) lockDomain(domain string) *syncs.Mutex {
	e.domainsMu.Lock()
	defer e.domainsMu.Unlock()
	if m, ok := e.domainLocks[domain]; ok {
		return m
	}
	m := new(syncs.Mutex)
	mak.Set(&e.domainLocks, domain, m)
	return m
}

// Go runs f in a new goroutine tracked by e.wg. [extension.Shutdown]
// waits for all such goroutines to finish.
func (e *extension) Go(f func()) {
	e.wg.Add(1)
	e.goroutinesStarted.Add(1)
	go func() {
		defer e.wg.Done()
		f()
	}()
}

// newExtension is the [ipnext.NewExtensionFn] registered for this
// feature. It is called once per [*ipnlocal.LocalBackend].
func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, featureName+": "),
	}, nil
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension].
func (e *extension) Init(ipnext.Host) error { return nil }

// Shutdown implements [ipnext.Extension]. It cancels the cert refresh
// loop if it's running, then waits for all in-flight goroutines
// (async renewals, refresh loop workers) to finish.
func (e *extension) Shutdown() error {
	e.mu.Lock()
	if e.certRefreshCancel != nil {
		e.certRefreshCancel()
		e.certRefreshCancel = nil
	}
	e.mu.Unlock()
	e.wg.Wait()
	return nil
}

// extFor returns the [*extension] for b, or an error if no acme
// extension is registered on b.
func extFor(b *ipnlocal.LocalBackend) (*extension, error) {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		return nil, errNoExt
	}
	return e, nil
}

// Hook adapter funcs that thread (b *ipnlocal.LocalBackend) into the
// extension's methods. These are what get installed in
// [ipnlocal.Hook*] at init time.

func getCertPEMHook(ctx context.Context, b *ipnlocal.LocalBackend, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
	e, err := extFor(b)
	if err != nil {
		return nil, err
	}
	pair, err := e.getCertPEMWithValidity(ctx, b, domain, minValidity)
	if err != nil {
		if ae, ok := errors.AsType[*xacme.Error](err); ok {
			if d, ok := xacme.RateLimit(ae); ok {
				return nil, certRateLimitedError{retryAfter: d, underlying: err}
			}
		}
		return nil, err
	}
	return pair, nil
}

func getACMETLSALPNCertHook(b *ipnlocal.LocalBackend, hi *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	e, err := extFor(b)
	if err != nil {
		return nil, false
	}
	return e.getACMETLSALPNCert(hi)
}

func getACMETLSALPNProtoHook(b *ipnlocal.LocalBackend, hi *tls.ClientHelloInfo) (string, bool) {
	e, err := extFor(b)
	if err != nil {
		return "", false
	}
	return e.getACMETLSALPNProto(hi)
}

func updateCertRefreshLoopHook(b *ipnlocal.LocalBackend, state ipn.State, sc ipn.ServeConfigView) {
	e, err := extFor(b)
	if err != nil {
		return
	}
	e.updateCertRefreshLoop(b, state, sc)
}

func shutdownCertRefreshLoopHook(b *ipnlocal.LocalBackend) {
	e, err := extFor(b)
	if err != nil {
		return
	}
	e.Shutdown()
}

func configureCertsForTestHook(b *ipnlocal.LocalBackend, getCert func(string) (*ipnlocal.TLSCertKeyPair, error)) {
	e, err := extFor(b)
	if err != nil {
		panic(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.getCertForTest = getCert
}

func handleC2NTLSCertStatus(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	e, err := extFor(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e.handleC2NTLSCertStatus(b, w, r)
}

// ACME / cert metrics. These are package-level (process-wide) because
// they aggregate across all [*extension]s in the process.
var (
	metricACMEDNS01Start       = clientmetric.NewCounter("cert_acme_dns01_start")
	metricACMEDNS01Success     = clientmetric.NewCounter("cert_acme_dns01_success")
	metricACMEDNS01Failure     = clientmetric.NewCounter("cert_acme_dns01_failure")
	metricACMETLSALPN01Start   = clientmetric.NewCounter("cert_acme_tls_alpn01_start")
	metricACMETLSALPN01Success = clientmetric.NewCounter("cert_acme_tls_alpn01_success")
	metricACMETLSALPN01Failure = clientmetric.NewCounter("cert_acme_tls_alpn01_failure")
)

// certPendingWarnable fires while ACME is fetching a TLS certificate
// for which no usable cached copy exists (initial issuance or after
// the cached cert has expired). Async renewal of a still-valid cert
// does not fire it.
var certPendingWarnable = health.Register(&health.Warnable{
	Code:     tsconst.HealthWarnableTLSCertPending,
	Title:    "Fetching TLS certificate",
	Severity: health.SeverityLow,
	Text: func(args health.Args) string {
		return "Fetching TLS certificate via ACME for: " + args[health.ArgDomains]
	},
})
