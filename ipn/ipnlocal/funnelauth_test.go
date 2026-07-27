// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
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

// signTestRS256JWT builds a compact RS256 JWS over claims signed by priv,
// with the given kid.
func signTestRS256JWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// jwksJSONForKey returns a JWKS document containing priv's public key.
func jwksJSONForKey(t *testing.T, priv *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	pub := priv.Public().(*rsa.PublicKey)
	eb := big.NewInt(int64(pub.E)).Bytes()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(eb),
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestParseJWKSAndVerifyRS256JWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"
	keys, err := parseJWKS(jwksJSONForKey(t, priv, kid))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys[kid]; !ok {
		t.Fatalf("parsed JWKS missing kid %q", kid)
	}

	keyFn := func(k string) (*rsa.PublicKey, error) {
		pk, ok := keys[k]
		if !ok {
			t.Fatalf("unknown kid %q", k)
		}
		return pk, nil
	}

	tok := signTestRS256JWT(t, priv, kid, map[string]any{"sub": "u1", "email": "a@b.com"})
	_, payload, err := verifyRS256JWT(tok, keyFn)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got["sub"] != "u1" {
		t.Errorf("sub = %v; want u1", got["sub"])
	}

	// Tampered payload must fail signature verification.
	parts := strings.Split(tok, ".")
	badPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	tampered := parts[0] + "." + badPayload + "." + parts[2]
	if _, _, err := verifyRS256JWT(tampered, keyFn); err == nil {
		t.Error("expected tampered token to fail verification")
	}

	// A token signed by a different key must fail.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokOther := signTestRS256JWT(t, other, kid, map[string]any{"sub": "u1"})
	if _, _, err := verifyRS256JWT(tokOther, keyFn); err == nil {
		t.Error("expected token signed by wrong key to fail verification")
	}

	// A non-RS256 alg must be rejected (algorithm-confusion guard).
	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"test-key-1"}`))
	noneTok := noneHdr + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + "."
	if _, _, err := verifyRS256JWT(noneTok, keyFn); err == nil {
		t.Error("expected alg=none token to be rejected")
	}
}

func TestAudienceClaimUnmarshal(t *testing.T) {
	var a audienceClaim
	if err := json.Unmarshal([]byte(`"one.ts.net"`), &a); err != nil {
		t.Fatal(err)
	}
	if !a.contains("one.ts.net") || a.contains("other") {
		t.Errorf("string aud parsed wrong: %v", a)
	}
	var b audienceClaim
	if err := json.Unmarshal([]byte(`["a.ts.net","b.ts.net"]`), &b); err != nil {
		t.Fatal(err)
	}
	if !b.contains("a.ts.net") || !b.contains("b.ts.net") {
		t.Errorf("array aud parsed wrong: %v", b)
	}
}

func TestFunnelPKCEChallenge(t *testing.T) {
	// Known RFC 7636 appendix B test vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := funnelPKCEChallenge(verifier); got != wantChallenge {
		t.Errorf("funnelPKCEChallenge = %q; want %q", got, wantChallenge)
	}
}

func TestFunnelRequestURLPinsHost(t *testing.T) {
	// funnelAuthAppendLoopParam must always re-pin to the funnel FQDN so a
	// tampered original URL cannot become an open redirect off this node.
	got := funnelAuthAppendLoopParam("https://evil.example.com/phish", "blog.ts.net")
	if !strings.HasPrefix(got, "https://blog.ts.net/") {
		t.Errorf("loop param URL = %q; want it pinned to blog.ts.net", got)
	}
	got2 := funnelAuthAppendLoopParam("https://blog.ts.net/page?x=1", "blog.ts.net")
	if !strings.HasPrefix(got2, "https://blog.ts.net/page") {
		t.Errorf("same-host URL not preserved: %q", got2)
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
