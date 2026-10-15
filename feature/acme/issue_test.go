// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/tstest/acmetest"
	"tailscale.com/types/logger"
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
