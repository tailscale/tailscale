// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn"
)

// TLSCertKeyPair is a TLS public and private key, and whether they were
// obtained from cache or freshly obtained.
type TLSCertKeyPair struct {
	CertPEM []byte // public key, in PEM form
	KeyPEM  []byte // private key, in PEM form
	Cached  bool   // whether result came from cache
}

// errNoCerts is returned by the wrapper methods below when ACME/cert
// support is not compiled into this build.
var errNoCerts = errors.New("cert support not compiled in this build")

// Hooks installed by the feature/acme package at init time. In builds
// without ACME support (js or ts_omit_acme), feature/acme is not linked
// in and these hooks remain unset; the wrapper methods below then
// behave as no-ops or return errNoCerts.
var (
	// HookGetCertPEM implements [LocalBackend.GetCertPEMWithValidity].
	HookGetCertPEM feature.Hook[func(ctx context.Context, b *LocalBackend, domain string, minValidity time.Duration) (*TLSCertKeyPair, error)]

	// HookGetACMETLSALPNCert returns the ACME tls-alpn-01 challenge
	// certificate for hi, if any.
	HookGetACMETLSALPNCert feature.Hook[func(b *LocalBackend, hi *tls.ClientHelloInfo) (*tls.Certificate, bool)]

	// HookGetACMETLSALPNProto reports whether the ACME ALPN protocol
	// should be advertised for hi.
	HookGetACMETLSALPNProto feature.Hook[func(b *LocalBackend, hi *tls.ClientHelloInfo) (string, bool)]

	// HookUpdateCertRefreshLoop is called when [LocalBackend]'s state
	// or serve config changes, so the cert refresh loop can be
	// (re)started or stopped. It is invoked with b.mu held.
	HookUpdateCertRefreshLoop feature.Hook[func(b *LocalBackend, state ipn.State, sc ipn.ServeConfigView)]

	// HookShutdownCertRefreshLoop is called from
	// [LocalBackend.Shutdown] to cancel the cert refresh loop.
	HookShutdownCertRefreshLoop feature.Hook[func(b *LocalBackend)]

	// HookConfigureCertsForTest implements
	// [LocalBackend.ConfigureCertsForTest].
	HookConfigureCertsForTest feature.Hook[func(b *LocalBackend, getCert func(string) (*TLSCertKeyPair, error))]

	// HookHandleC2NTLSCertStatus handles the GET /tls-cert-status
	// control-to-node request.
	HookHandleC2NTLSCertStatus feature.Hook[func(b *LocalBackend, w http.ResponseWriter, r *http.Request)]
)

func init() {
	RegisterC2N("GET /tls-cert-status", func(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
		if f, ok := HookHandleC2NTLSCertStatus.GetOk(); ok {
			f(b, w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"Missing":true}`) // a minimal tailcfg.C2NTLSCertInfo
	})
}

// GetCertPEM returns a TLSCertKeyPair for domain, either from the local
// cache or by issuing a new cert via ACME. See
// [LocalBackend.GetCertPEMWithValidity] for the full semantics.
func (b *LocalBackend) GetCertPEM(ctx context.Context, domain string) (*TLSCertKeyPair, error) {
	return b.GetCertPEMWithValidity(ctx, domain, 0)
}

// GetCertPEMWithValidity is like [LocalBackend.GetCertPEM] but with a
// minimum cert validity duration. If the cached cert would expire
// sooner than minValidity, it is renewed synchronously.
//
// The domain must be one of:
//
//   - An exact CertDomain (e.g., "node.ts.net")
//   - A wildcard domain (e.g., "*.node.ts.net")
//   - A bring-your-own Funnel domain referenced by the local serve
//     config (e.g., "foo.com" when ServeConfig.AllowFunnel has
//     "foo.com:443").
//
// On an ACME rate-limit failure the returned error implements
// [tsweb.HTTPStatuser] with a 429 + Retry-After response; other errors
// are returned unchanged.
func (b *LocalBackend) GetCertPEMWithValidity(ctx context.Context, domain string, minValidity time.Duration) (*TLSCertKeyPair, error) {
	if f, ok := HookGetCertPEM.GetOk(); ok {
		return f(ctx, b, domain, minValidity)
	}
	return nil, errNoCerts
}

// getACMETLSALPNCert returns the short-lived ACME challenge certificate
// for hi.ServerName, if any. The ok result reports whether hi offered
// acme-tls/1 and an ACME order is actively waiting on that challenge
// for hi.ServerName.
func (b *LocalBackend) getACMETLSALPNCert(hi *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	if f, ok := HookGetACMETLSALPNCert.GetOk(); ok {
		return f(b, hi)
	}
	return nil, false
}

// getACMETLSALPNProto reports whether serveTLSConfig should advertise
// an ACME ALPN protocol for this ClientHello.
func (b *LocalBackend) getACMETLSALPNProto(hi *tls.ClientHelloInfo) (string, bool) {
	if f, ok := HookGetACMETLSALPNProto.GetOk(); ok {
		return f(b, hi)
	}
	return "", false
}

// updateCertRefreshLoopLocked is called when b.state or b.serveConfig
// changes, so the cert refresh loop can be (re)started or stopped.
// b.mu must be held.
func (b *LocalBackend) updateCertRefreshLoopLocked() {
	if f, ok := HookUpdateCertRefreshLoop.GetOk(); ok {
		f(b, b.state, b.serveConfig)
	}
}

// shutdownCertRefreshLoopLocked is called from
// [LocalBackend.Shutdown] to cancel the cert refresh loop.
// b.mu must be held.
func (b *LocalBackend) shutdownCertRefreshLoopLocked() {
	if f, ok := HookShutdownCertRefreshLoop.GetOk(); ok {
		f(b)
	}
}

// serveTLSNextProtos returns the baseline ALPN protocols for ordinary
// Serve TLS traffic. ACME tls-alpn-01 is intentionally not advertised
// here; it is added dynamically by serveTLSConfig only while a matching
// challenge certificate is pending.
func serveTLSNextProtos() []string {
	return []string{"h2", "http/1.1"}
}
