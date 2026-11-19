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

	"tailscale.com/ipn/ipnlocal"
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

// dns01TestEnv wires an extension and an acmetest server for a dns-01
// issuance: SetDNS writes into a map the server validates against, and
// both the publish and the Accept are timestamped.
type dns01TestEnv struct {
	e      *extension
	s      *acmetest.Server
	logs   []string
	logsMu sync.Mutex

	mu        sync.Mutex
	records   map[string][]string
	published []time.Time
	accepted  []time.Time
}

func newDNS01TestEnv(t *testing.T, settle time.Duration) *dns01TestEnv {
	t.Helper()
	env := &dns01TestEnv{records: map[string][]string{}}
	env.s = acmetest.Start(t)
	env.s.LookupTXT = func(name string) []string {
		env.mu.Lock()
		defer env.mu.Unlock()
		return env.records[strings.TrimSuffix(name, ".")]
	}
	env.s.Validate = func(identifier, challengeType string) error {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.accepted = append(env.accepted, time.Now())
		name := "_acme-challenge." + strings.TrimPrefix(identifier, "*.")
		if len(env.records[name]) == 0 {
			return errors.New("No TXT record found at " + name)
		}
		return nil
	}
	env.e = &extension{
		logf:      t.Logf,
		dnsSettle: settle,
		setDNS: func(ctx context.Context, b *ipnlocal.LocalBackend, name, value string) error {
			env.mu.Lock()
			defer env.mu.Unlock()
			env.records[name] = append(env.records[name], value)
			env.published = append(env.published, time.Now())
			return nil
		},
		lookupTXT: func(ctx context.Context, name string) ([]string, error) { return nil, nil },
	}
	return env
}

func (env *dns01TestEnv) logf(format string, args ...any) {
	env.logsMu.Lock()
	env.logs = append(env.logs, fmt.Sprintf(format, args...))
	env.logsMu.Unlock()
}

func (env *dns01TestEnv) settleLogs() int {
	env.logsMu.Lock()
	defer env.logsMu.Unlock()
	n := 0
	for _, line := range env.logs {
		if strings.Contains(line, "for the DNS record to propagate") {
			n++
		}
	}
	return n
}

func (env *dns01TestEnv) issue(ctx context.Context, t *testing.T, domain string) (*ipnlocal.TLSCertKeyPair, error) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(env.s.Root())
	return env.e.issueACMECert(ctx, nil, newTestACMEClient(t, env.s), acmeCertIssueArgs{
		cs:            certStateStore{StateStore: new(mem.Store), testRoots: roots},
		logf:          env.logf,
		domain:        domain,
		challengeType: acmeChallengeDNS01,
	})
}

// TestIssueACMECertDNS01SettlesBeforeAccept checks that a dns-01
// issuance waits dnsSettle between publishing the TXT record and asking
// the CA to validate it.
func TestIssueACMECertDNS01SettlesBeforeAccept(t *testing.T) {
	const settle = 100 * time.Millisecond
	env := newDNS01TestEnv(t, settle)
	pair, err := env.issue(context.Background(), t, "example.com")
	if err != nil {
		t.Fatalf("issueACMECert: %v", err)
	}
	if pair == nil || len(pair.CertPEM) == 0 {
		t.Fatal("no certificate issued")
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.published) != 1 || len(env.accepted) != 1 {
		t.Fatalf("published %d, accepted %d; want 1 and 1", len(env.published), len(env.accepted))
	}
	if gap := env.accepted[0].Sub(env.published[0]); gap < settle {
		t.Errorf("Accept came %v after SetDNS; want at least %v", gap, settle)
	}
	if n := env.settleLogs(); n != 1 {
		t.Errorf("settle logged %d times, want 1", n)
	}
}

// TestIssueACMECertDNS01WildcardSettlesOnce checks that a wildcard order,
// whose two authorizations share one TXT record name, publishes both
// values and waits once.
func TestIssueACMECertDNS01WildcardSettlesOnce(t *testing.T) {
	env := newDNS01TestEnv(t, 50*time.Millisecond)
	if _, err := env.issue(context.Background(), t, "*.example.com"); err != nil {
		t.Fatalf("issueACMECert: %v", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if got := env.records["_acme-challenge.example.com"]; len(got) != 2 {
		t.Errorf("TXT values at _acme-challenge.example.com = %d, want 2", len(got))
	}
	if len(env.accepted) != 2 {
		t.Errorf("accepted %d challenges, want 2", len(env.accepted))
	}
	if n := env.settleLogs(); n != 1 {
		t.Errorf("settle logged %d times, want 1", n)
	}
}

// TestIssueACMECertDNS01SkipsSettleForExistingRecord checks that when the
// pre-check finds the TXT record already published, neither SetDNS nor
// the settle runs.
func TestIssueACMECertDNS01SkipsSettleForExistingRecord(t *testing.T) {
	env := newDNS01TestEnv(t, time.Hour)
	ac := newTestACMEClient(t, env.s)
	// The pre-check skips SetDNS only for the exact value the CA wants.
	// The token is fixed by acmetest's ID sequence, so compute that value
	// the way the client will.
	rec, err := ac.DNS01ChallengeRecord("token-3")
	if err != nil {
		t.Fatal(err)
	}
	env.e.lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		return []string{rec}, nil
	}
	env.e.setDNS = func(ctx context.Context, b *ipnlocal.LocalBackend, name, value string) error {
		t.Errorf("SetDNS(%q) called; the pre-check should have found the record", name)
		return nil
	}
	env.s.Validate = nil
	env.s.LookupTXT = func(name string) []string { return []string{rec} }

	roots := x509.NewCertPool()
	roots.AddCert(env.s.Root())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := env.e.issueACMECert(ctx, nil, ac, acmeCertIssueArgs{
		cs:            certStateStore{StateStore: new(mem.Store), testRoots: roots},
		logf:          env.logf,
		domain:        "example.com",
		challengeType: acmeChallengeDNS01,
	}); err != nil {
		t.Fatalf("issueACMECert: %v", err)
	}
	if n := env.settleLogs(); n != 0 {
		t.Errorf("settle logged %d times, want 0", n)
	}
}

// TestIssueACMECertDNS01SettleHonorsContext checks that cancelling the
// issuance during the settle returns promptly without accepting.
func TestIssueACMECertDNS01SettleHonorsContext(t *testing.T) {
	env := newDNS01TestEnv(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	orig := env.e.setDNS
	env.e.setDNS = func(ctx2 context.Context, b *ipnlocal.LocalBackend, name, value string) error {
		err := orig(ctx2, b, name, value)
		cancel() // the settle starts right after publishing
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, err := env.issue(ctx, t, "example.com")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("issuance did not return after cancellation during the settle")
	}
	if n := env.s.Requests("/challenge/3"); n != 0 {
		t.Errorf("challenge was accepted %d times; want 0", n)
	}
}
