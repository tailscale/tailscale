// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
)

const (
	testPeerA = tailcfg.StableNodeID("nAAAAAAACNTRL")
	testPeerB = tailcfg.StableNodeID("nBBBBBBBCNTRL")
)

// consentTestManager returns a manager with consent enabled, along with the
// clock driving it and a counter of consent notifications sent.
func consentTestManager(t *testing.T) (m *manager, clock *tstest.Clock, notifies *atomic.Int64) {
	t.Helper()
	fo, err := newFileOps(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock = tstest.NewClock(tstest.ClockOpts{Start: time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC)})
	var n atomic.Int64
	m = managerOptions{
		Logf:                  t.Logf,
		Clock:                 tstime.DefaultClock{Clock: clock},
		State:                 &mem.Store{},
		fileOps:               fo,
		AllowExternalTaildrop: func() bool { return true },
		ConsentForOwnDevices:  func() bool { return true },
		NotifyConsent:         func() { n.Add(1) },
	}.New()
	t.Cleanup(m.Shutdown)
	return m, clock, &n
}

// approve resolves the manager's single pending request and returns the token
// issued for the named file.
func approve(t *testing.T, m *manager, name string, size int64) *ConsentToken {
	t.Helper()
	pending := m.pendingConsentRequests()
	if len(pending) != 1 {
		t.Fatalf("pending requests = %d; want 1", len(pending))
	}
	if err := m.resolveConsent(pending[0].RequestID, true); err != nil {
		t.Fatalf("resolveConsent: %v", err)
	}
	state, tok, err := m.requestConsent(testPeerA, "peer-a", name, testConsentMetadata(name, size))
	if err != nil {
		t.Fatalf("requestConsent after approve: %v", err)
	}
	if state != ConsentApproved {
		t.Fatalf("state after approve = %q; want %q", state, ConsentApproved)
	}
	if tok == nil {
		t.Fatal("approved with no token")
	}
	return tok
}

// consentHeaders builds the headers a sender presents on a consented PUT.
func consentHeaders(tok *ConsentToken) http.Header {
	return http.Header{
		hdrConsentTxID:    []string{tok.TxID},
		hdrConsentToken:   []string{tok.Token},
		hdrConsentNonce:   []string{tok.Nonce},
		hdrConsentExpires: []string{tok.ExpiresAt.Format(time.RFC3339)},
	}
}

// TestConsentForOwnDevices verifies that the manager's consentForOwnDevices method
// returns the correct value based on the AllowExternalTaildrop and ConsentForOwnDevices options.
// Typically, self-owned devices do not require consent, but this can be overridden for testing
// or development purposes.
func TestConsentForOwnDevices(t *testing.T) {
	tests := []struct {
		name     string
		optIn    func() bool
		override func() bool
		want     bool
	}{
		{
			name: "default",
		},
		{
			name:     "override_without_opt_in",
			override: func() bool { return true },
		},
		{
			name:  "opt_in_without_override",
			optIn: func() bool { return true },
		},
		{
			name:     "opt_in_with_override",
			optIn:    func() bool { return true },
			override: func() bool { return true },
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := managerOptions{Logf: t.Logf, AllowExternalTaildrop: tt.optIn, ConsentForOwnDevices: tt.override}.New()
			t.Cleanup(m.Shutdown)
			if got := m.consentForOwnDevices(); got != tt.want {
				t.Errorf("consentForOwnDevices = %v; want %v", got, tt.want)
			}
		})
	}
}

// TestConsentApproveAndConsume verifies that approving a request issues a
// single-use token, and that polling does not generate duplicate prompts.
func TestConsentApproveAndConsume(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		size     int64
	}{
		{name: "small_file", filename: "foo.txt", size: 5},
		{name: "larger_file", filename: "report.pdf", size: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, notifies := consentTestManager(t)

			state, tok, err := m.requestConsent(testPeerA, "peer-a", tt.filename, testConsentMetadata(tt.filename, tt.size))
			if err != nil {
				t.Fatal(err)
			}
			if state != ConsentPending {
				t.Fatalf("state = %q; want %q", state, ConsentPending)
			}
			if tok != nil {
				t.Error("pending request came with a token")
			}
			if notifies.Load() != 1 {
				t.Errorf("notifies = %d; want 1", notifies.Load())
			}

			// Polling must not re-prompt.
			if _, _, err := m.requestConsent(testPeerA, "peer-a", tt.filename, testConsentMetadata(tt.filename, tt.size)); err != nil {
				t.Fatal(err)
			}
			if notifies.Load() != 1 {
				t.Errorf("notifies after poll = %d; want 1", notifies.Load())
			}

			tok = approve(t, m, tt.filename, tt.size)

			nonce, err := m.beginConsentedPut(testPeerA, tt.filename, consentHeaders(tok), 0, tt.size)
			if err != nil {
				t.Fatalf("beginConsentedPut: %v", err)
			}
			m.endConsentedPut(nonce, tt.size, nil)

			// One consent, one transfer: the same token must not work twice.
			if _, err := m.beginConsentedPut(testPeerA, tt.filename, consentHeaders(tok), 0, tt.size); err != ErrConsentConsumed {
				t.Errorf("second use error = %v; want %v", err, ErrConsentConsumed)
			}

			// Nothing is pending once decided.
			if got := m.pendingConsentRequests(); len(got) != 0 {
				t.Errorf("pending after approval = %d; want 0", len(got))
			}
		})
	}
}

// TestConsentDeny verifies that denied requests remain denied and cannot be
// resolved again.
func TestConsentDeny(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		size     int64
	}{
		{name: "small_file", filename: "foo.txt", size: 5},
		{name: "larger_file", filename: "report.pdf", size: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)

			if _, _, err := m.requestConsent(testPeerA, "peer-a", tt.filename, testConsentMetadata(tt.filename, tt.size)); err != nil {
				t.Fatal(err)
			}
			pending := m.pendingConsentRequests()
			if len(pending) != 1 {
				t.Fatalf("pending = %d; want 1", len(pending))
			}
			if err := m.resolveConsent(pending[0].RequestID, false); err != nil {
				t.Fatal(err)
			}

			state, tok, err := m.requestConsent(testPeerA, "peer-a", tt.filename, testConsentMetadata(tt.filename, tt.size))
			if err != nil {
				t.Fatal(err)
			}
			if state != ConsentDenied {
				t.Errorf("state = %q; want %q", state, ConsentDenied)
			}
			if tok != nil {
				t.Error("denied request came with a token")
			}

			// A decision may only be made once.
			if err := m.resolveConsent(pending[0].RequestID, true); err != ErrConsentConsumed {
				t.Errorf("second resolve error = %v; want %v", err, ErrConsentConsumed)
			}
			// An unknown ID is reported, not silently ignored.
			if err := m.resolveConsent("nope", true); err != ErrConsentUnknown {
				t.Errorf("unknown resolve error = %v; want %v", err, ErrConsentUnknown)
			}
		})
	}
}

// TestConsentTokenTampering verifies that consent tokens reject altered,
// malformed, missing, or mismatched transfer metadata.
func TestConsentTokenTampering(t *testing.T) {
	tests := []struct {
		name     string
		sender   tailcfg.StableNodeID
		filename string
		length   int64
		mutate   func(*ConsentToken, http.Header)
		wantErr  error
	}{
		{
			name:     "good",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
		},
		{
			name:     "wrong_sender",
			sender:   testPeerB,
			filename: "foo.txt",
			length:   100,
			wantErr:  ErrConsentMismatch,
		},
		{
			name:     "wrong_filename",
			sender:   testPeerA,
			filename: "bar.txt",
			length:   100,
			wantErr:  ErrConsentMismatch,
		},
		{
			name:     "wrong_size",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   99,
			wantErr:  ErrConsentMismatch,
		},
		{
			name:     "unknown_length",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   -1,
			wantErr:  ErrConsentMismatch,
		},
		{
			name:     "flipped_token",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
			mutate: func(tok *ConsentToken, hdr http.Header) {
				raw, _ := base64.RawURLEncoding.DecodeString(tok.Token)
				raw[0] ^= 0x80
				hdr.Set(hdrConsentToken, base64.RawURLEncoding.EncodeToString(raw))
			},
			wantErr: ErrConsentInvalid,
		},
		{
			name:     "no_headers",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
			mutate: func(_ *ConsentToken, hdr http.Header) {
				clear(hdr)
			},
			wantErr: ErrConsentRequired,
		},
		{
			name:     "shifted_expiry",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
			mutate: func(tok *ConsentToken, hdr http.Header) {
				hdr.Set(hdrConsentExpires, tok.ExpiresAt.Add(time.Hour).Format(time.RFC3339))
			},
			wantErr: ErrConsentMismatch,
		},
		{
			name:     "malformed_token",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
			mutate: func(_ *ConsentToken, hdr http.Header) {
				hdr.Set(hdrConsentToken, "!!!not-base64!!!")
			},
			wantErr: ErrConsentMalformed,
		},
		{
			name:     "malformed_nonce",
			sender:   testPeerA,
			filename: "foo.txt",
			length:   100,
			mutate: func(_ *ConsentToken, hdr http.Header) {
				hdr.Set(hdrConsentNonce, "!!!not-base64!!!")
			},
			wantErr: ErrConsentMalformed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)
			hdr := consentHeaders(tok)
			if tt.mutate != nil {
				tt.mutate(tok, hdr)
			}
			if _, err := m.beginConsentedPut(tt.sender, tt.filename, hdr, 0, tt.length); err != tt.wantErr {
				t.Errorf("beginConsentedPut = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

// TestConsentUnknownNonce verifies that unrecognized consent nonces are rejected.
func TestConsentUnknownNonce(t *testing.T) {
	tests := []struct {
		name      string
		nonceByte byte
	}{
		{name: "zero_nonce", nonceByte: 0},
		{name: "nonzero_nonce", nonceByte: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			var zero [32]byte
			for i := range zero {
				zero[i] = tt.nonceByte
			}
			hdr := http.Header{
				hdrConsentToken:   []string{base64.RawURLEncoding.EncodeToString(zero[:])},
				hdrConsentNonce:   []string{base64.RawURLEncoding.EncodeToString(zero[:])},
				hdrConsentExpires: []string{time.Now().Add(time.Minute).Format(time.RFC3339)},
			}
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", hdr, 0, 100); err != ErrConsentUnknown {
				t.Errorf("err = %v; want %v", err, ErrConsentUnknown)
			}
		})
	}
}

// TestConsentExpiry verifies that approved consent tokens are accepted before
// expiry and rejected at or after expiry.
func TestConsentExpiry(t *testing.T) {
	tests := []struct {
		name    string
		delay   time.Duration
		wantErr error
	}{
		{name: "before_expiry", delay: consentTokenTTL - time.Nanosecond},
		{name: "at_expiry", delay: consentTokenTTL, wantErr: ErrConsentExpired},
		{name: "after_expiry", delay: consentTokenTTL + time.Second, wantErr: ErrConsentExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, clock, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)

			clock.Advance(tt.delay)
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100); err != tt.wantErr {
				t.Errorf("err = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

// TestConsentPendingExpiry verifies that pending requests disappear and can no
// longer be resolved once their pending lifetime expires.
func TestConsentPendingExpiry(t *testing.T) {
	tests := []struct {
		name        string
		delay       time.Duration
		wantPending int
		wantErr     error
	}{
		{name: "before_expiry", delay: consentPendingTTL - time.Nanosecond, wantPending: 1},
		{name: "at_expiry", delay: consentPendingTTL, wantErr: ErrConsentUnknown},
		{name: "after_expiry", delay: consentPendingTTL + time.Second, wantErr: ErrConsentUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, clock, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			pending := m.pendingConsentRequests()
			if len(pending) != 1 {
				t.Fatalf("pending = %d; want 1", len(pending))
			}

			clock.Advance(tt.delay)
			if got := m.pendingConsentRequests(); len(got) != tt.wantPending {
				t.Errorf("pending after expiry = %d; want %d", len(got), tt.wantPending)
			}
			// Only requests that have not expired can still be decided.
			if err := m.resolveConsent(pending[0].RequestID, true); err != tt.wantErr {
				t.Errorf("resolve expired error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

// TestConsentConcurrentPutRejected verifies that a token cannot start two
// concurrent transfers, but may be retried after a failed transfer.
func TestConsentConcurrentPutRejected(t *testing.T) {
	tests := []struct {
		name    string
		failure error
	}{
		{name: "unexpected_eof", failure: io.ErrUnexpectedEOF},
		{name: "closed_connection", failure: io.ErrClosedPipe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)

			nonce, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100); err != ErrConsentConsumed {
				t.Errorf("concurrent use error = %v; want %v", err, ErrConsentConsumed)
			}
			// A failed transfer releases the record rather than burning it.
			m.endConsentedPut(nonce, 0, tt.failure)
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100); err != nil {
				t.Errorf("retry after failure: %v", err)
			}
		})
	}
}

// TestConsentResume verifies that an approved transfer can resume after a
// failed attempt and is consumed only after the complete file arrives.
func TestConsentResume(t *testing.T) {
	tests := []struct {
		name     string
		received int64
	}{
		{name: "restart", received: 0},
		{name: "partial", received: 60},
		{name: "all_bytes_before_failure", received: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)

			// The first attempt fails after receiving the specified prefix.
			nonce, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			m.endConsentedPut(nonce, tt.received, io.ErrUnexpectedEOF)

			// The same consent covers the rest, so the user isn't asked twice for one
			// file.
			nonce, err = m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), tt.received, 100-tt.received)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			m.endConsentedPut(nonce, 100, nil)

			// Now that the whole file has arrived, it is spent.
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100); err != ErrConsentConsumed {
				t.Errorf("after completion err = %v; want %v", err, ErrConsentConsumed)
			}
		})
	}
}

// TestConsentResumeBeyondProgress verifies that resumptions cannot claim an
// offset beyond the bytes actually received.
func TestConsentResumeBeyondProgress(t *testing.T) {
	tests := []struct {
		name   string
		offset int64
	}{
		{name: "one_byte", offset: 1},
		{name: "partial_file", offset: 40},
		{name: "whole_file", offset: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", testConsentMetadata("foo.txt", 100)); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)

			// Claiming an offset past what we've actually received would let a sender
			// leave a hole in the file.
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), tt.offset, 100-tt.offset); err != ErrConsentMismatch {
				t.Errorf("err = %v; want %v", err, ErrConsentMismatch)
			}
		})
	}
}

// TestConsentSecretPersists verifies that the consent signing secret is
// persisted and reused by managers sharing a state store.
func TestConsentSecretPersists(t *testing.T) {
	tests := []struct {
		name    string
		preload bool
	}{
		{name: "new_secret"},
		{name: "existing_secret", preload: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mem.Store{}
			if tt.preload {
				if err := store.WriteState(ipn.TaildropConsentSecretKey, []byte("01234567890123456789012345678901")); err != nil {
					t.Fatal(err)
				}
			}
			newMgr := func() *manager {
				return managerOptions{
					Logf:                  t.Logf,
					State:                 store,
					AllowExternalTaildrop: func() bool { return true },
					ConsentForOwnDevices:  func() bool { return true },
				}.New()
			}

			m1 := newMgr()
			s1, err := m1.consentSecret()
			if err != nil {
				t.Fatal(err)
			}
			m1.Shutdown()

			m2 := newMgr()
			s2, err := m2.consentSecret()
			if err != nil {
				t.Fatal(err)
			}
			m2.Shutdown()

			if s1 != s2 {
				t.Error("consent secret changed across managers sharing a state store")
			}
			if s1 == ([32]byte{}) {
				t.Error("consent secret is all zeros")
			}
			b, err := store.ReadState(ipn.TaildropConsentSecretKey)
			if err != nil {
				t.Fatalf("secret not persisted: %v", err)
			}
			if len(b) != 32 {
				t.Errorf("persisted secret length = %d; want 32", len(b))
			}
		})
	}
}

// TestConsentSecretWithoutStateStore verifies that a manager without a state
// store generates and caches a nonzero in-memory consent secret.
func TestConsentSecretWithoutStateStore(t *testing.T) {
	tests := []struct {
		name  string
		reads int
	}{
		{name: "initial", reads: 1},
		{name: "cached", reads: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := managerOptions{Logf: t.Logf, AllowExternalTaildrop: func() bool { return true }, ConsentForOwnDevices: func() bool { return true }}.New()
			t.Cleanup(m.Shutdown)
			s, err := m.consentSecret()
			if err != nil {
				t.Fatalf("consentSecret with no state store: %v", err)
			}
			for range tt.reads - 1 {
				got, err := m.consentSecret()
				if err != nil || got != s {
					t.Fatalf("cached secret changed: %v", err)
				}
			}
			if s == ([32]byte{}) {
				t.Error("consent secret is all zeros")
			}
		})
	}
}

// TestConsentTokenBindsToIssuer verifies that a token issued by one manager
// cannot be used with another manager.
func TestConsentTokenBindsToIssuer(t *testing.T) {
	tests := []struct {
		name        string
		otherIssuer bool
		wantErr     error
	}{
		{name: "issuing_node"}, {name: "different_node", otherIssuer: true, wantErr: ErrConsentUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := consentTestManager(t)
			req := testConsentMetadata("foo.txt", 100)
			if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", req); err != nil {
				t.Fatal(err)
			}
			tok := approve(t, m, "foo.txt", 100)
			if tt.otherIssuer {
				m, _, _ = consentTestManager(t)
				if _, _, err := m.requestConsent(testPeerA, "peer-a", "foo.txt", req); err != nil {
					t.Fatal(err)
				}
				approve(t, m, "foo.txt", 100)
			}
			if _, err := m.beginConsentedPut(testPeerA, "foo.txt", consentHeaders(tok), 0, 100); err != tt.wantErr {
				t.Errorf("beginConsentedPut = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

// testConsentMetadata supplies stable transactions for polling tests.
func testConsentMetadata(name string, size int64) PutRequest {
	content := ""
	switch size {
	case 2:
		content = "hi"
	case 4:
		content = "abcd"
	case 5:
		content = "hello"
	case 11:
		content = "hello world"
	}
	return PutRequest{Size: size, TxID: name, Hash: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
}

// TestConsentIndependentDecisions verifies that consent decisions are scoped to
// individual files: approving or denying one request does not affect another.
func TestConsentIndependentDecisions(t *testing.T) {
	m, _, notifies := consentTestManager(t)
	a, b := testConsentMetadata("a", 1), testConsentMetadata("b", 1)
	if _, _, err := m.requestConsent(testPeerA, "peer", "a", a); err != nil {
		t.Fatal(err)
	}
	shown := m.pendingConsentRequests()[0]
	if _, _, err := m.requestConsent(testPeerA, "peer", "b", b); err != nil {
		t.Fatal(err)
	}
	pending := m.pendingConsentRequests()
	if len(pending) != 2 || notifies.Load() != 2 {
		t.Fatalf("pending=%v, notifications=%d", pending, notifies.Load())
	}
	for _, req := range pending {
		if len(req.Files) != 1 || req.TotalSize != 1 {
			t.Fatalf("request=%v", req)
		}
	}
	if err := m.resolveConsent(shown.RequestID, true); err != nil {
		t.Fatal(err)
	}
	state, token, err := m.requestConsent(testPeerA, "peer", "a", a)
	if err != nil || state != ConsentApproved || token == nil {
		t.Fatalf("approved file: %v, %v, %v", state, token, err)
	}
	state, token, err = m.requestConsent(testPeerA, "peer", "b", b)
	if err != nil || state != ConsentPending || token != nil {
		t.Fatalf("other file: %v, %v, %v", state, token, err)
	}
	if err := m.resolveConsent(m.pendingConsentRequests()[0].RequestID, false); err != nil {
		t.Fatal(err)
	}
	state, token, err = m.requestConsent(testPeerA, "peer", "b", b)
	if err != nil || state != ConsentDenied || token != nil {
		t.Fatalf("denied file: %v, %v, %v", state, token, err)
	}
	state, token, err = m.requestConsent(testPeerA, "peer", "a", a)
	if err != nil || state != ConsentApproved || token == nil {
		t.Fatalf("other decision changed approval: %v, %v, %v", state, token, err)
	}
}

// TestConsentExpiryLifecycle verifies that pending requests expire into denied
// tombstones, which are later reclaimed after the terminal-record retention period.
func TestConsentExpiryLifecycle(t *testing.T) {
	m, clock, notifies := consentTestManager(t)
	req := testConsentMetadata("a", 1)
	m.requestConsent(testPeerA, "peer", "a", req)
	before := notifies.Load()
	clock.Advance(consentPendingTTL)
	if err := tstest.WaitFor(time.Second, func() error {
		if notifies.Load() <= before {
			return fmt.Errorf("no expiry notification")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(m.pendingConsentRequests()) != 0 {
		t.Fatal("expired prompt still visible")
	}
	for range 3 {
		state, token, err := m.requestConsent(testPeerA, "peer", "a", req)
		if err != nil || state != ConsentDenied || token != nil {
			t.Fatalf("expired poll: %v %v", state, err)
		}
		clock.Advance(time.Second)
	}
	clock.Advance(consentTerminalTTL)
	if err := tstest.WaitFor(time.Second, func() error {
		m.consent.mu.Lock()
		defer m.consent.mu.Unlock()
		if len(m.consent.requests) != 0 {
			return fmt.Errorf("terminal records not reclaimed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestConsentAdmissionLimits verifies per-peer, global, and rate admission
// limits, while allowing idempotent polling of an already queued request.
func TestConsentAdmissionLimits(t *testing.T) {
	for _, scope := range []string{"peer", "global", "rate"} {
		t.Run(scope, func(t *testing.T) {
			m, clock, _ := consentTestManager(t)
			limit := maxConsentPeerFiles
			if scope != "peer" {
				limit = maxConsentFiles
			}
			for i := range limit + 1 {
				peer := testPeerA
				if scope != "peer" {
					peer = tailcfg.StableNodeID(fmt.Sprintf("peer-%d", i))
				}
				name := fmt.Sprintf("file-%d", i)
				_, _, err := m.requestConsent(peer, "peer", name, testConsentMetadata(name, 1))
				if i == limit {
					if err != ErrConsentLimit {
						t.Fatalf("limit error = %v", err)
					}
				} else if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				if scope == "rate" && err == nil {
					pending := m.pendingConsentRequests()
					if len(pending) != 1 {
						t.Fatalf("pending requests = %d, want 1", len(pending))
					}
					if err := m.resolveConsent(pending[0].RequestID, false); err != nil {
						t.Fatal(err)
					}
				} else if scope != "rate" {
					clock.Advance(100 * time.Millisecond)
				}
			}
			// Idempotent polling must still work with a full queue.
			peer := testPeerA
			if scope != "peer" {
				peer = "peer-0"
			}
			if _, _, err := m.requestConsent(peer, "peer", "file-0", testConsentMetadata("file-0", 1)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestConsentExpiryAfterSleep verifies that a large clock jump, such as after
// device sleep, clears expired prompts and notifies the GUI to dismiss them.
func TestConsentExpiryAfterSleep(t *testing.T) {
	m, clock, notifies := consentTestManager(t)
	m.requestConsent(testPeerA, "peer", "a", testConsentMetadata("a", 1))
	before := notifies.Load()
	// Timers may not run while the machine sleeps, including past the
	// tombstone retention deadline. The GUI must still dismiss its prompt.
	clock.Advance(consentPendingTTL + consentTerminalTTL + time.Second)
	if err := tstest.WaitFor(time.Second, func() error {
		if notifies.Load() <= before {
			return fmt.Errorf("no clearing notification after sleep")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(m.pendingConsentRequests()) != 0 {
		t.Fatal("expired prompt remains")
	}
}

// Expiry must free abandoned approvals without another lookup of their IDs.
func TestOutboundConsentCache(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	var cache outboundConsentCache
	t.Cleanup(cache.Clear)
	key := outboundConsentKey{TxID: "abandoned"}
	token := &ConsentToken{Nonce: "first", ExpiresAt: clock.Now().Add(time.Minute)}
	cache.store(clock.Now(), key, token)
	if cache.canResume(key, token) {
		t.Fatal("fresh approval can resume an earlier transfer")
	}
	cache.start(key, token)
	cache.store(clock.Now(), key, token)
	if !cache.canResume(key, token) {
		t.Fatal("repeated approval lost upload history")
	}
	replacement := &ConsentToken{Nonce: "replacement", ExpiresAt: token.ExpiresAt}
	cache.store(clock.Now(), key, replacement)
	if cache.canResume(key, replacement) || cache.canResume(key, token) {
		t.Fatal("replacement approval retained earlier upload history")
	}
	clock.Advance(time.Minute)
	// Looking up an unrelated ID must also remove the abandoned grant.
	cache.load(clock.Now(), outboundConsentKey{TxID: "unrelated"})
	if len(cache.entries) != 0 {
		t.Fatalf("read retained %d expired entries", len(cache.entries))
	}

	// Writes prune abandoned grants too, while preserving live approvals.
	liveKey := outboundConsentKey{TxID: "live"}
	cache.store(clock.Now(), key, &ConsentToken{ExpiresAt: clock.Now().Add(time.Minute)})
	cache.store(clock.Now(), liveKey, &ConsentToken{ExpiresAt: clock.Now().Add(time.Hour)})
	clock.Advance(time.Minute)
	cache.store(clock.Now(), outboundConsentKey{TxID: "new"}, &ConsentToken{ExpiresAt: clock.Now().Add(time.Hour)})
	if len(cache.entries) != 2 || cache.entries[key] != nil || cache.entries[liveKey] == nil {
		t.Fatalf("write did not prune only expired entries: %v", cache.entries)
	}
	cache.Clear()

	// Bound live approvals too; retain the newly inserted grant.
	for i := range maxOutboundConsent + 10 {
		key = outboundConsentKey{TxID: fmt.Sprint(i)}
		cache.store(clock.Now(), key, &ConsentToken{Nonce: key.TxID, ExpiresAt: clock.Now().Add(time.Hour)})
	}
	cache.mu.Lock()
	n := len(cache.entries)
	cache.mu.Unlock()
	if n != maxOutboundConsent || cache.load(clock.Now(), key) == nil {
		t.Fatalf("cache size=%d or newest token missing", n)
	}
	cache.Clear()
	if cache.load(clock.Now(), key) != nil {
		t.Fatal("Clear retained a token")
	}
}
