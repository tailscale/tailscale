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
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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

// TestIssueACMECertRetriesWithoutReplaces checks that a renewal order the
// CA rejects for its ARI "replaces" field is retried once without it, and
// that the cert from the retried order is stored.
// See tailscale/tailscale#22042.
func TestIssueACMECertRetriesWithoutReplaces(t *testing.T) {
	const domain = "example.com"
	prev := &x509.Certificate{AuthorityKeyId: []byte{1, 2, 3}, SerialNumber: big.NewInt(42)}
	tests := []struct {
		name         string
		replaces     *x509.Certificate
		rejectCode   int    // if non-zero, status for orders naming "replaces"
		rejectType   string // ACME problem type for rejected orders
		rejectPlain  bool   // also reject orders that don't name "replaces"
		wantErr      string // "replaces=<bool>" detail of the rejected order whose error is returned, or "" for success
		wantReplaces []bool // whether each new order request named "replaces"
	}{
		{
			name:         "no_previous_cert",
			wantReplaces: []bool{false},
		},
		{
			name:         "replaces_accepted",
			replaces:     prev,
			wantReplaces: []bool{true},
		},
		{
			name:         "account_mismatch_retries_without_replaces",
			replaces:     prev,
			rejectCode:   http.StatusForbidden,
			rejectType:   "unauthorized",
			wantReplaces: []bool{true, false},
		},
		{
			name:         "already_replaced_retries_without_replaces",
			replaces:     prev,
			rejectCode:   http.StatusConflict,
			rejectType:   "alreadyReplaced",
			wantReplaces: []bool{true, false},
		},
		{
			name:         "plain_order_rejected_too",
			replaces:     prev,
			rejectCode:   http.StatusBadRequest,
			rejectType:   "rejectedIdentifier",
			rejectPlain:  true,
			wantErr:      "replaces=false",
			wantReplaces: []bool{true, false},
		},
		{
			name:         "rate_limited_not_retried",
			replaces:     prev,
			rejectCode:   http.StatusTooManyRequests,
			rejectType:   "rateLimited",
			wantErr:      "replaces=true",
			wantReplaces: []bool{true},
		},
		{
			name:         "server_error_not_retried",
			replaces:     prev,
			rejectCode:   http.StatusInternalServerError,
			rejectType:   "serverInternal",
			wantErr:      "replaces=true",
			wantReplaces: []bool{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				mu          sync.Mutex
				gotReplaces []bool
				s           *acmetest.Server
			)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/new-order" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("reading new-order request: %v", err)
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					var jws struct {
						Payload string `json:"payload"`
					}
					if err := json.Unmarshal(body, &jws); err != nil {
						t.Errorf("decoding JWS: %v", err)
					}
					payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
					if err != nil {
						t.Errorf("decoding JWS payload: %v", err)
					}
					var req struct {
						Replaces string `json:"replaces"`
					}
					if err := json.Unmarshal(payload, &req); err != nil {
						t.Errorf("decoding order: %v", err)
					}
					named := req.Replaces != ""
					mu.Lock()
					gotReplaces = append(gotReplaces, named)
					mu.Unlock()
					if tt.rejectCode != 0 && (named || tt.rejectPlain) {
						w.Header().Set("Content-Type", "application/problem+json")
						w.WriteHeader(tt.rejectCode)
						fmt.Fprintf(w, `{"type":"urn:ietf:params:acme:error:%s","detail":"replaces=%v"}`, tt.rejectType, named)
						return
					}
				}
				s.ServeHTTP(w, r)
			}))
			t.Cleanup(ts.Close)
			s = acmetest.New(ts.URL)
			s.ChallengeType = "tls-alpn-01"

			ac := newTestACMEClient(t, s)
			// Return rate limits and server errors straight away.
			ac.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return 0 }
			roots := x509.NewCertPool()
			roots.AddCert(s.Root())
			cs := certStateStore{StateStore: new(mem.Store), testRoots: roots}
			e := &extension{logf: t.Logf}
			_, err := e.issueACMECert(t.Context(), nil, ac, acmeCertIssueArgs{
				cs:            cs,
				logf:          t.Logf,
				domain:        domain,
				replaces:      tt.replaces,
				challengeType: acmeChallengeTLSALPN01,
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("issueACMECert: %v", err)
				}
				if _, err := cs.Read(domain, time.Now()); err != nil {
					t.Errorf("stored certificate does not read back: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("issueACMECert error = %v, want it to contain %q", err, tt.wantErr)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(gotReplaces, tt.wantReplaces) {
				t.Errorf("new order requests naming replaces = %v, want %v", gotReplaces, tt.wantReplaces)
			}
		})
	}
}
