// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"testing"
	"time"

	"tailscale.com/types/key"
)

// testFunnelAuthKeys builds funnelAuthKeys directly from a fixed machine key,
// bypassing LocalBackend so the crypto can be tested in isolation.
func testFunnelAuthKeys(t *testing.T) *funnelAuthKeys {
	t.Helper()
	mk := key.NewMachine()
	secret := mk.UntypedBytes()
	salt := []byte("tailscale-funnel-auth:test-profile")
	sess, err := deriveFunnelAEAD(secret, salt, "session-cookie-v1")
	if err != nil {
		t.Fatal(err)
	}
	st, err := deriveFunnelAEAD(secret, salt, "login-state-v1")
	if err != nil {
		t.Fatal(err)
	}
	return &funnelAuthKeys{session: sess, state: st}
}

func TestFunnelSessionSealOpenRoundTrip(t *testing.T) {
	k := testFunnelAuthKeys(t)
	now := time.Now()
	want := &funnelAuthSession{
		Sub:           "user-123",
		Email:         "alice@example.com",
		EmailVerified: true,
		Name:          "Alice",
		Tailnet:       "example.com",
		FQDN:          "blog.tailXXXX.ts.net",
		Expiry:        now.Add(time.Hour).Unix(),
	}
	tok, err := k.sealFunnelSession(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.openFunnelSession(tok, want.FQDN, now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if *got != *want {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestFunnelSessionTamperRejected(t *testing.T) {
	k := testFunnelAuthKeys(t)
	now := time.Now()
	s := &funnelAuthSession{Sub: "u", FQDN: "h.ts.net", Expiry: now.Add(time.Hour).Unix()}
	tok, err := k.sealFunnelSession(s)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the token.
	b := []byte(tok)
	b[len(b)/2] ^= 0x01
	if _, err := k.openFunnelSession(string(b), s.FQDN, now); err == nil {
		t.Fatal("expected error opening tampered token, got nil")
	}
}

func TestFunnelSessionExpiryRejected(t *testing.T) {
	k := testFunnelAuthKeys(t)
	now := time.Now()
	s := &funnelAuthSession{Sub: "u", FQDN: "h.ts.net", Expiry: now.Add(-time.Second).Unix()}
	tok, err := k.sealFunnelSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.openFunnelSession(tok, s.FQDN, now); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestFunnelSessionCrossHostRejected(t *testing.T) {
	k := testFunnelAuthKeys(t)
	now := time.Now()
	s := &funnelAuthSession{Sub: "u", FQDN: "a.ts.net", Expiry: now.Add(time.Hour).Unix()}
	tok, err := k.sealFunnelSession(s)
	if err != nil {
		t.Fatal(err)
	}
	// A cookie sealed for a.ts.net must not open as b.ts.net (AAD binding),
	// nor pass the explicit FQDN check.
	if _, err := k.openFunnelSession(tok, "b.ts.net", now); err == nil {
		t.Fatal("expected cross-host session to be rejected")
	}
}

func TestFunnelSessionWrongKeyRejected(t *testing.T) {
	k1 := testFunnelAuthKeys(t)
	k2 := testFunnelAuthKeys(t)
	now := time.Now()
	s := &funnelAuthSession{Sub: "u", FQDN: "h.ts.net", Expiry: now.Add(time.Hour).Unix()}
	tok, err := k1.sealFunnelSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.openFunnelSession(tok, s.FQDN, now); err == nil {
		t.Fatal("expected session sealed with a different key to be rejected")
	}
}

func TestFunnelStateSealOpenRoundTrip(t *testing.T) {
	k := testFunnelAuthKeys(t)
	now := time.Now()
	const fqdn = "blog.tailXXXX.ts.net"
	want := &funnelAuthState{
		OrigURL:      "https://blog.tailXXXX.ts.net/secret?x=1",
		CodeVerifier: "verifier-abc",
		Nonce:        "nonce-xyz",
		CSRF:         "csrf-123",
		Expiry:       now.Add(funnelStateTTL).Unix(),
	}
	tok, err := k.sealFunnelState(want, fqdn)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.openFunnelState(tok, fqdn, now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if *got != *want {
		t.Errorf("state round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	// State sealed for one host must not open for another.
	if _, err := k.openFunnelState(tok, "other.ts.net", now); err == nil {
		t.Fatal("expected cross-host state to be rejected")
	}
}

func TestFunnelAuthAllowed(t *testing.T) {
	tests := []struct {
		name          string
		allow         []string
		email         string
		emailVerified bool
		tailnet       string
		want          bool
	}{
		{name: "empty allowlist admits anyone", allow: nil, email: "x@y.com", want: true},
		{name: "exact match", allow: []string{"alice@example.com"}, email: "alice@example.com", want: true},
		{name: "exact match case-insensitive", allow: []string{"Alice@Example.com"}, email: "alice@example.com", want: true},
		{name: "exact no-match", allow: []string{"alice@example.com"}, email: "bob@example.com", want: false},
		{name: "exact match ignores email_verified", allow: []string{"alice@example.com"}, email: "alice@example.com", emailVerified: false, want: true},
		{name: "domain match verified", allow: []string{"*@example.com"}, email: "bob@example.com", emailVerified: true, want: true},
		{name: "domain reject unverified", allow: []string{"*@example.com"}, email: "bob@example.com", emailVerified: false, want: false},
		{name: "domain reject emailish (@github)", allow: []string{"*@github"}, email: "bob@github", emailVerified: true, want: false},
		{name: "domain no-match", allow: []string{"*@example.com"}, email: "bob@other.com", emailVerified: true, want: false},
		{name: "tailnet match", allow: []string{"tailnet:example.com"}, tailnet: "example.com", want: true},
		{name: "tailnet no-match", allow: []string{"tailnet:example.com"}, tailnet: "other.com", want: false},
		{name: "multi-entry one matches", allow: []string{"x@a.com", "*@b.com"}, email: "y@b.com", emailVerified: true, want: true},
		{name: "empty entries ignored", allow: []string{"", "  ", "alice@example.com"}, email: "alice@example.com", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := funnelAuthAllowed(tt.allow, tt.email, tt.emailVerified, tt.tailnet)
			if got != tt.want {
				t.Errorf("funnelAuthAllowed(%q, %q, %v, %q) = %v; want %v",
					tt.allow, tt.email, tt.emailVerified, tt.tailnet, got, tt.want)
			}
		})
	}
}

func TestIsRealEmailDomain(t *testing.T) {
	tests := []struct {
		dom  string
		want bool
	}{
		{"example.com", true},
		{"a.b.example.com", true},
		{"github", false},
		{"", false},
		{"has@at.com", false},
		{"nodot", false},
	}
	for _, tt := range tests {
		if got := isRealEmailDomain(tt.dom); got != tt.want {
			t.Errorf("isRealEmailDomain(%q) = %v; want %v", tt.dom, got, tt.want)
		}
	}
}
