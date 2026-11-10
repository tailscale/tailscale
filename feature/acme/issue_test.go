// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/tstest/acmetest"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

func newTestACMEClient(t *testing.T, s *acmetest.Server) *xacme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &xacme.Client{Key: key, DirectoryURL: s.DirectoryURL()}
}

// TestIssueACMECertSurfacesAuthorizationError checks that when the CA
// marks the authorization invalid, the error returned to the caller is
// the authorization's problem detail, not just the order's status.
// See tailscale/tailscale#21759.
func TestIssueACMECertSurfacesAuthorizationError(t *testing.T) {
	const domain = "example.com"
	const detail = `Incorrect TXT record "abc" (and 29 more) found at _acme-challenge.example.com`
	s := acmetest.Start(t)
	s.ChallengeType = "tls-alpn-01"
	s.Validate = func(identifier, challengeType string) error { return errors.New(detail) }

	e := &extension{logf: t.Logf}
	var logged atomic.Bool
	logf := func(format string, args ...any) {
		if strings.Contains(fmt.Sprintf(format, args...), "WaitAuthorization") {
			logged.Store(true)
		}
		t.Logf(format, args...)
	}
	_, err := e.issueACMECert(context.Background(), nil, newTestACMEClient(t, s), acmeCertIssueArgs{
		cs:            certStateStore{StateStore: new(mem.Store)},
		logf:          logf,
		domain:        domain,
		challengeType: acmeChallengeTLSALPN01,
	})
	if err == nil {
		t.Fatal("issueACMECert succeeded; want an authorization error")
	}
	var ae *xacme.AuthorizationError
	if !errors.As(err, &ae) {
		t.Fatalf("error is %T, want *acme.AuthorizationError: %v", err, err)
	}
	if !strings.Contains(err.Error(), detail) {
		t.Errorf("error does not carry the CA's challenge detail:\n got: %v\nwant substring: %s", err, detail)
	}
	if !strings.Contains(err.Error(), domain) {
		t.Errorf("error does not name the identifier %q: %v", domain, err)
	}
	// The first order is ID 1; see [acmetest.Server.Requests].
	if n := s.Requests("/order/1"); n != 0 {
		t.Errorf("order was polled %d times; the authorization error should be reported before WaitOrder", n)
	}
	if !logged.Load() {
		t.Error("the WaitAuthorization failure was not logged")
	}
}

// TestIssueACMECertValidAuthorization checks that waiting on the
// authorizations does not disturb the happy path: a valid authorization
// leads to a finalized order and a stored certificate.
func TestIssueACMECertValidAuthorization(t *testing.T) {
	const domain = "example.com"
	s := acmetest.Start(t)
	s.ChallengeType = "tls-alpn-01"

	e := &extension{logf: t.Logf}
	roots := x509.NewCertPool()
	roots.AddCert(s.Root())
	cs := certStateStore{StateStore: new(mem.Store), testRoots: roots}
	pair, err := e.issueACMECert(context.Background(), nil, newTestACMEClient(t, s), acmeCertIssueArgs{
		cs:            cs,
		logf:          logger.Logf(t.Logf),
		domain:        domain,
		challengeType: acmeChallengeTLSALPN01,
	})
	if err != nil {
		t.Fatalf("issueACMECert: %v", err)
	}
	if pair == nil || len(pair.CertPEM) == 0 || len(pair.KeyPEM) == 0 {
		t.Fatalf("issueACMECert returned an incomplete pair: %+v", pair)
	}
	// The first order is ID 1 and its authorization ID 2.
	if n := s.Requests("/authz/2"); n < 2 {
		t.Errorf("authorization was fetched %d times; want the initial fetch plus at least one WaitAuthorization poll", n)
	}
	if _, err := cs.Read(domain, time.Now()); err != nil {
		t.Errorf("stored certificate does not read back: %v", err)
	}
}

// replacesRejectingCA returns a fake CA that refuses any newOrder carrying
// the ARI "replaces" field with the given problem document, and a count of
// the orders it has refused. Orders without the field are served normally.
func replacesRejectingCA(t *testing.T, code int, problemType, detail string) (*acmetest.Server, *atomic.Int64) {
	t.Helper()
	var (
		s        *acmetest.Server
		rejected atomic.Int64
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == httpm.POST && r.URL.Path == "/new-order" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading newOrder body: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			if orderReplaces(t, body) != "" {
				n := rejected.Add(1)
				w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-rejected-%d", n))
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(code)
				fmt.Fprintf(w, `{"status":%d,"type":"urn:ietf:params:acme:error:%s","detail":%q}`, code, problemType, detail)
				return
			}
		}
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	s = acmetest.New(ts.URL)
	return s, &rejected
}

// orderReplaces returns the "replaces" field of a JWS-wrapped ACME newOrder
// request body, or the empty string if the order does not carry one.
func orderReplaces(t *testing.T, body []byte) string {
	t.Helper()
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		t.Errorf("decoding newOrder JWS: %v", err)
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		t.Errorf("decoding newOrder JWS payload: %v", err)
		return ""
	}
	var order struct {
		Replaces string `json:"replaces"`
	}
	if err := json.Unmarshal(payload, &order); err != nil {
		t.Errorf("decoding newOrder payload %q: %v", payload, err)
		return ""
	}
	return order.Replaces
}

// TestIssueACMECertRetriesWithoutReplaces checks that a renewal whose ARI
// "replaces" claim the CA refuses is ordered again without the claim.
// Nothing on disk says which ACME account issued a cached cert, so if the
// account key is recreated while the cert stays, the CA refuses the claim on
// every renewal until the cert expires.
// See tailscale/tailscale#22042.
func TestIssueACMECertRetriesWithoutReplaces(t *testing.T) {
	const domain = "example.com"
	s, rejected := replacesRejectingCA(t, http.StatusForbidden, "unauthorized",
		"requester account did not request the certificate being replaced by this order")
	s.ChallengeType = "tls-alpn-01"

	e := &extension{logf: t.Logf}
	roots := x509.NewCertPool()
	roots.AddCert(s.Root())
	cs := certStateStore{StateStore: new(mem.Store), testRoots: roots}
	args := acmeCertIssueArgs{
		cs:            cs,
		logf:          logger.Logf(t.Logf),
		domain:        domain,
		challengeType: acmeChallengeTLSALPN01,
	}

	// Issue a cert to renew, the way a first issuance does: no previous
	// cert, so no "replaces" claim.
	pair, err := e.issueACMECert(context.Background(), nil, newTestACMEClient(t, s), args)
	if err != nil {
		t.Fatalf("initial issueACMECert: %v", err)
	}
	prevCrt, err := parseCertificate(pair)
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}

	// Renew it under a fresh account key, claiming that cert as replaced.
	args.replacesCert = prevCrt
	pair, err = e.issueACMECert(context.Background(), nil, newTestACMEClient(t, s), args)
	if err != nil {
		t.Fatalf("renewal issueACMECert: %v", err)
	}
	if pair == nil || len(pair.CertPEM) == 0 || len(pair.KeyPEM) == 0 {
		t.Fatalf("renewal returned an incomplete pair: %+v", pair)
	}
	if n := rejected.Load(); n != 1 {
		t.Errorf("the CA refused %d orders claiming a replaced cert, want 1", n)
	}
}

// TestIssueACMECertKeepsReplacesWhenRateLimited checks that a rate-limited
// order is not retried without the "replaces" claim: a second order would be
// rate limited too, and it would give up the renewal exemption the claim is
// there to earn.
func TestIssueACMECertKeepsReplacesWhenRateLimited(t *testing.T) {
	const domain = "example.com"
	s, rejected := replacesRejectingCA(t, http.StatusTooManyRequests, "rateLimited",
		"too many certificates already issued for this domain")
	s.ChallengeType = "tls-alpn-01"

	e := &extension{logf: t.Logf}
	roots := x509.NewCertPool()
	roots.AddCert(s.Root())
	cs := certStateStore{StateStore: new(mem.Store), testRoots: roots}
	args := acmeCertIssueArgs{
		cs:            cs,
		logf:          logger.Logf(t.Logf),
		domain:        domain,
		challengeType: acmeChallengeTLSALPN01,
	}

	pair, err := e.issueACMECert(context.Background(), nil, newTestACMEClient(t, s), args)
	if err != nil {
		t.Fatalf("initial issueACMECert: %v", err)
	}
	prevCrt, err := parseCertificate(pair)
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}

	// A 429 is retriable, so the ACME client itself keeps re-posting the
	// same order until it gives up. Stop after the first response, to
	// observe what issueACMECert does with the error.
	ac := newTestACMEClient(t, s)
	ac.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return 0 }

	args.replacesCert = prevCrt
	if _, err := e.issueACMECert(context.Background(), nil, ac, args); err == nil {
		t.Fatal("renewal issueACMECert succeeded; want the rate-limit error")
	} else {
		var ae *xacme.Error
		if !errors.As(err, &ae) {
			t.Fatalf("error is %T, want *acme.Error: %v", err, err)
		}
		if ae.StatusCode != http.StatusTooManyRequests {
			t.Errorf("error carries HTTP %d, want %d: %v", ae.StatusCode, http.StatusTooManyRequests, err)
		}
	}
	if n := rejected.Load(); n != 1 {
		t.Errorf("the CA refused %d orders claiming a replaced cert, want 1 with no retry", n)
	}
}
