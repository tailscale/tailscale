// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package acme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/acmetest"
	"tailscale.com/types/netmap"
	"tailscale.com/util/must"
)

// issuanceTestBackend returns a test backend with the acme extension, a
// temp cert store, a frozen clock, and a netmap advertising the given
// CertDomains. The returned clock only advances via [tstest.Clock.Advance].
func issuanceTestBackend(t *testing.T, certDomains ...string) (*ipnlocal.LocalBackend, *tstest.Clock) {
	t.Helper()
	b := ipnlocaltest.NewBackend(t)
	b.SetVarRoot(t.TempDir())
	b.ForTest().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{}).View(),
		DNS:      tailcfg.DNSConfig{CertDomains: certDomains},
	})
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Date(2025, time.May, 1, 0, 0, 0, 0, time.UTC)})
	b.ForTest().SetClock(clock)
	return b, clock
}

// TestIssuanceBackoffAfterFailedSetDNS verifies that after a failed
// issuance with no usable cert on disk (here: the dns-01 challenge's
// SetDNS call fails, as with the control-side 500s of #20823), further
// requests for the domain do not immediately start a new ACME order
// (and SetDNS call); they get a 429 rate-limit error for a backoff
// window that grows on repeated failures. See tailscale/tailscale#22021.
func TestIssuanceBackoffAfterFailedSetDNS(t *testing.T) {
	tstest.AssertNotParallel(t)

	const domain = "example.com"
	s := acmetest.Start(t)
	s.ChallengeType = "dns-01"
	t.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", s.DirectoryURL())

	b, clock := issuanceTestBackend(t, domain)
	newOrders := func() int { return s.Requests("/new-order") }

	// The first request starts an order, then fails at SetDNS (the test
	// backend has no control connection).
	_, err := b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if err == nil || !strings.Contains(err.Error(), "SetDNS") {
		t.Fatalf("first GetCertPEMWithValidity error = %v, want a SetDNS failure", err)
	}
	if got := newOrders(); got != 1 {
		t.Fatalf("new-order requests = %d after first request, want 1", got)
	}

	// Requests inside the backoff window must not start a new order;
	// each would also burn a new SetDNS call. They get a 429 with a
	// Retry-After instead.
	for range 5 {
		_, err := b.GetCertPEMWithValidity(context.Background(), domain, 0)
		rl, ok := errors.AsType[certRateLimitedError](err)
		if !ok {
			t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError", err, err)
		}
		if rl.retryAfter <= 0 || rl.retryAfter > issuanceBackoffBase {
			t.Fatalf("retryAfter = %v, want in (0, %v]", rl.retryAfter, issuanceBackoffBase)
		}
	}
	if got := newOrders(); got != 1 {
		t.Fatalf("new-order requests = %d after 5 more requests in the backoff window, want 1", got)
	}

	// Once the window expires, a new attempt is allowed; its failure
	// grows the window.
	clock.Advance(issuanceBackoffBase + time.Second)
	_, err = b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if err == nil {
		t.Fatal("GetCertPEMWithValidity after window expiry succeeded, want a SetDNS failure")
	}
	if _, ok := errors.AsType[certRateLimitedError](err); ok {
		t.Fatalf("GetCertPEMWithValidity error = %v, want a fresh issuance attempt, not backoff", err)
	}
	if got := newOrders(); got != 2 {
		t.Fatalf("new-order requests = %d after backoff window expired, want 2", got)
	}

	_, err = b.GetCertPEMWithValidity(context.Background(), domain, 0)
	rl, ok := errors.AsType[certRateLimitedError](err)
	if !ok {
		t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError", err, err)
	}
	if rl.retryAfter <= issuanceBackoffBase {
		t.Fatalf("retryAfter = %v after second failure, want > %v (window must grow)", rl.retryAfter, issuanceBackoffBase)
	}
	if got := newOrders(); got != 2 {
		t.Fatalf("new-order requests = %d inside the grown window, want 2", got)
	}
}

// TestIssuanceBackoffHonorsCARateLimitRetryAfter verifies that the
// existing CA 429 + Retry-After behaviour (#20315) is preserved: the
// first response surfaces the CA's Retry-After, and the issuance backoff
// window it arms never undercuts it. See tailscale/tailscale#22021.
func TestIssuanceBackoffHonorsCARateLimitRetryAfter(t *testing.T) {
	tstest.AssertNotParallel(t)

	const (
		domain     = "example.com"
		retryAfter = 3600 * time.Second
	)
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Replay-Nonce", "nonce")
			w.WriteHeader(http.StatusOK)
			return
		}
		requests.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"too many certificates already issued"}`))
	}))
	defer srv.Close()
	t.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", srv.URL)

	b, _ := issuanceTestBackend(t, domain)

	// The first issuance is rate-limited by the CA. The ACME client
	// retries 429s internally until the context is done, so bound it.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := b.GetCertPEMWithValidity(ctx, domain, 0)
	rl, ok := errors.AsType[certRateLimitedError](err)
	if !ok {
		t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError", err, err)
	}
	if rl.retryAfter != retryAfter {
		t.Fatalf("retryAfter = %v, want %v from the CA's Retry-After header", rl.retryAfter, retryAfter)
	}

	// A request inside the backoff window is also a 429, is answered
	// without hitting the CA, and does not undercut the CA's Retry-After.
	// The context is bounded in case the backoff is (incorrectly) absent
	// and the request reaches the CA, whose 429s the ACME client would
	// otherwise retry for as long as the context lives.
	before := requests.Load()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	_, err = b.GetCertPEMWithValidity(ctx2, domain, 0)
	if rl, ok := errors.AsType[certRateLimitedError](err); !ok {
		t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError", err, err)
	} else if rl.retryAfter < retryAfter {
		t.Fatalf("retryAfter = %v, want >= %v (CA Retry-After must be honoured)", rl.retryAfter, retryAfter)
	}
	if got := requests.Load() - before; got != 0 {
		t.Fatalf("%d requests to the CA during the backoff window, want 0", got)
	}
}

// TestIssuanceBackoffResetBySuccess verifies that a successful issuance
// clears the backoff so that a later failure gets a fresh issuance
// attempt with the base window again. See tailscale/tailscale#22021.
func TestIssuanceBackoffResetBySuccess(t *testing.T) {
	tstest.AssertNotParallel(t)

	const (
		tsNetDomain = "node.ts.net"
		domain      = "foo.com" // BYO Funnel domain; issued via tls-alpn-01
	)
	s := acmetest.Start(t)
	s.ChallengeType = "tls-alpn-01"
	t.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", s.DirectoryURL())

	b, clock := issuanceTestBackend(t, tsNetDomain)
	// Enable Funnel for the BYO domain on :443 so issuance uses
	// tls-alpn-01 rather than dns-01 (which needs a control connection).
	funnel := map[ipn.HostPort]bool{ipn.HostPort(domain + ":443"): true}
	b.ForTest().SetServeConfig((&ipn.ServeConfig{AllowFunnel: funnel}).View())
	newOrders := func() int { return s.Requests("/new-order") }

	// The CA rejects the challenge, so the first issuance fails and arms
	// the backoff.
	validationErr := errors.New("simulated CA validation failure")
	s.Validate = func(identifier, challengeType string) error { return validationErr }
	_, err := b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if err == nil || !strings.Contains(err.Error(), validationErr.Error()) {
		t.Fatalf("first GetCertPEMWithValidity error = %v, want the CA validation failure", err)
	}
	if got := newOrders(); got != 1 {
		t.Fatalf("new-order requests = %d after first request, want 1", got)
	}
	_, err = b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if _, ok := errors.AsType[certRateLimitedError](err); !ok {
		t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError during backoff", err, err)
	}
	if got := newOrders(); got != 1 {
		t.Fatalf("new-order requests = %d during backoff, want 1", got)
	}

	// After the window expires, the CA is healthy again and the issuance
	// succeeds, clearing the backoff.
	clock.Advance(issuanceBackoffBase + time.Second)
	s.Validate = nil
	pair, err := b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if err != nil {
		t.Fatalf("GetCertPEMWithValidity after backoff expiry: %v", err)
	}
	if len(pair.CertPEM) == 0 || len(pair.KeyPEM) == 0 {
		t.Fatalf("GetCertPEMWithValidity = %+v, want a cert/key pair", pair)
	}
	if got := newOrders(); got != 2 {
		t.Fatalf("new-order requests = %d after successful issuance, want 2", got)
	}

	// With the backoff reset, the next failure gets a fresh issuance
	// attempt (not the stale backoff) and re-arms the base window.
	os.RemoveAll(must.Get(certDir(b)))
	s.Validate = func(identifier, challengeType string) error { return validationErr }
	_, err = b.GetCertPEMWithValidity(context.Background(), domain, 0)
	if err == nil || strings.Contains(err.Error(), "not retrying until") {
		t.Fatalf("GetCertPEMWithValidity error = %v, want a fresh issuance failure, not backoff", err)
	}
	if got := newOrders(); got != 3 {
		t.Fatalf("new-order requests = %d after success reset the backoff, want 3", got)
	}
	_, err = b.GetCertPEMWithValidity(context.Background(), domain, 0)
	rl, ok := errors.AsType[certRateLimitedError](err)
	if !ok {
		t.Fatalf("GetCertPEMWithValidity error = %v (%T), want certRateLimitedError", err, err)
	}
	if rl.retryAfter <= 0 || rl.retryAfter > issuanceBackoffBase {
		t.Fatalf("retryAfter = %v after first failure post-reset, want in (0, %v]", rl.retryAfter, issuanceBackoffBase)
	}
	if got := newOrders(); got != 3 {
		t.Fatalf("new-order requests = %d inside the re-armed window, want 3", got)
	}
}
