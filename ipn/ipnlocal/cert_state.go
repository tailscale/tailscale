// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/syncs"
	"tailscale.com/util/set"
)

// CertState holds the per-[LocalBackend] state owned by the
// feature/acme extension. The struct lives in this package so that
// cert.go can access its fields directly without method indirection,
// while the extension in feature/acme remains the canonical owner.
//
// In builds without ACME support (js or ts_omit_acme), no extension
// constructs a CertState, and [LocalBackend.certState] returns nil.
//
// CertState is safe for concurrent use; the individual fields document
// their own synchronization.
//
// TODO(bradfitz): continue moving all this cert code into feature/acme's package.
// This type being here was a compromise to keep the PR small during the move.
type CertState struct {
	// acmeMu serializes ACME operations so concurrent requests for
	// certs don't slam ACME. The first goroutine through populates the
	// on-disk cache and the rest reuse it.
	acmeMu syncs.Mutex

	// renewMu guards renewCertAt.
	// Lock order: acmeMu before renewMu.
	renewMu     syncs.Mutex
	renewCertAt map[string]time.Time // lazily initialized under renewMu

	// pendingACMETLSALPNCerts maps SNI names to short-lived ACME
	// tls-alpn-01 challenge certificates while an ACME order is
	// waiting for validation. Entries are deleted by the cleanup
	// function returned from storeACMETLSALPNCert after the challenge
	// validation path finishes, whether it succeeds or fails.
	pendingACMETLSALPNCerts syncs.Map[string, *tls.Certificate] // "foo.bar.com" => challenge cert

	// pendingCertDomains tracks the set of domains for which an ACME
	// issuance is currently in flight with no usable cached cert. It
	// backs the tls-cert-pending health Warnable.
	// Guarded by pendingCertDomainsMu.
	pendingCertDomainsMu sync.Mutex
	pendingCertDomains   set.Set[string]

	// getCertForTest is used to retrieve TLS certificates in tests.
	// See [forTest.ConfigureCerts]. Guarded by the containing
	// [LocalBackend]'s mutex (b.mu).
	getCertForTest func(hostname string) (*TLSCertKeyPair, error)

	// certRefreshCancel cancels the background TLS cert refresh loop
	// that periodically pokes [LocalBackend.GetCertPEM] so renewals
	// happen on idle nodes. Guarded by the containing [LocalBackend]'s
	// mutex (b.mu). Non-nil while the loop is running.
	certRefreshCancel context.CancelFunc
}

// hookCertState is set by the feature/acme extension at init time
// to a function that returns the [CertState] for backend b, or nil
// if the cert extension is not registered (e.g. in builds with
// ts_omit_acme or js).
var hookCertState feature.Hook[func(*LocalBackend) *CertState]

// HookCertState exposes [hookCertState] to the feature/acme package
// for installation. It must be set exactly once at init time.
var HookCertState = &hookCertState

// certState returns the cert state for b, or nil if the cert
// extension is not registered.
func (b *LocalBackend) certState() *CertState {
	if f, ok := hookCertState.GetOk(); ok {
		return f(b)
	}
	return nil
}
