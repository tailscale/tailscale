// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
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

// Manual end-to-end verification (requires a dev control plane seeded with the
// "tailscale-funnel" OIDC client and the oidc-authorization-flow feature flag;
// see the cross-repo contract). The automated tests above cover the node-side
// gate, cookie, JWKS/JWT verification, and allowlist in isolation; a full
// browser round trip needs the corp side live:
//
//  1. On a funnel-capable node: `tailscale funnel --auth 3000` (serve any local
//     app on :3000). Confirm status shows "auth: Login With Tailscale".
//  2. From a browser with no Tailscale installed, open https://<node>.ts.net/.
//     Expect a 302 to control's /a/oauth_authorize, sign in, and land back on
//     the app; the URL briefly carries ts_funnel_authed=1.
//  3. Confirm the backend app receives Tailscale-User-Login / -Email headers.
//  4. Reload: no re-auth (the ts_funnel_session cookie is reused). Open a fresh
//     browser / clear cookies: re-auth is required (stateless session).
//  5. `tailscale funnel --auth --allow=you@example.com 3000`: allowed user still
//     works; a different Tailscale account gets a clean 403.
//  6. Visit https://<node>.ts.net/.well-known/tailscale/funnel-auth/logout: the
//     session cookie is cleared and the next request re-authenticates.
//  7. Regression: `tailscale funnel 3000` (no --auth) serves with no redirect;
//     a raw-TCP funnel (`tailscale funnel --tcp=...`) is unaffected.

// funnelReq builds a Funnel request to the given path for host example.ts.net,
// with an optional session cookie value.
func funnelReq(t *testing.T, path, cookie string) *http.Request {
	t.Helper()
	u, err := url.Parse("https://example.ts.net" + path)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   "example.ts.net",
		Header: make(http.Header),
		TLS:    &tls.ConnectionState{ServerName: "example.ts.net"},
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: funnelSessionCookieName, Value: cookie})
	}
	req = req.WithContext(serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{
		Funnel:   &funnelFlow{Host: "example.ts.net"},
		SrcAddr:  netip.MustParseAddrPort("1.2.3.4:1234"),
		DestPort: 443,
	}))
	return req
}

// TestFunnelGateEndToEnd exercises the security-critical gate paths through
// serveWebHandler: unauthenticated bounce, valid-session admission, reserved
// path interception (vs. app routes), allowlist rejection, and the
// redirect-loop guard.
func TestFunnelGateEndToEnd(t *testing.T) {
	backendHit := false
	testServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.Header().Set("X-Backend", "1")
		w.Header().Set("Echo-User-Login", r.Header.Get("Tailscale-User-Login"))
		w.Header().Set("Echo-User-Email", r.Header.Get("Tailscale-User-Email"))
	}))
	defer testServ.Close()

	b := newTestBackend(t)
	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"example.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {
					Proxy: testServ.URL,
					Auth:  &ipn.FunnelAuth{Provider: "tailscale", Allow: []string{"alice@example.com"}},
				},
				// An app route that lives under the reserved prefix must never
				// be reachable; the interceptor owns the whole prefix.
				funnelAuthReservedPrefix + "sneaky": {Proxy: testServ.URL},
			}},
		},
		AllowFunnel: map[ipn.HostPort]bool{"example.ts.net:443": true},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}
	keys, err := b.funnelAuthKeys()
	if err != nil {
		t.Fatal(err)
	}
	mint := func(sess *funnelAuthSession) string {
		v, err := keys.sealFunnelSession(sess)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	now := time.Now()

	t.Run("no session bounces to control authorize", func(t *testing.T) {
		backendHit = false
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, "/private", ""))
		res := w.Result()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("status = %d; want 302", res.StatusCode)
		}
		loc := res.Header.Get("Location")
		if !strings.Contains(loc, "/a/oauth_authorize") ||
			!strings.Contains(loc, "client_id=tailscale-funnel") ||
			!strings.Contains(loc, "code_challenge_method=S256") {
			t.Errorf("unexpected authorize redirect: %s", loc)
		}
		if backendHit {
			t.Error("backend must not be hit for an unauthenticated request")
		}
		// A state cookie must be set to carry CSRF.
		if len(res.Cookies()) == 0 {
			t.Error("expected a state cookie to be set")
		}
	})

	t.Run("valid allowed session is admitted and identity forwarded", func(t *testing.T) {
		backendHit = false
		tok := mint(&funnelAuthSession{
			Sub: "u1", Email: "alice@example.com", EmailVerified: true,
			Name: "Alice", FQDN: "example.ts.net", Expiry: now.Add(time.Hour).Unix(),
		})
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, "/private", tok))
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; want 200", res.StatusCode)
		}
		if !backendHit {
			t.Error("backend should have been reached for a valid session")
		}
		if got := res.Header.Get("Echo-User-Login"); got != "alice@example.com" {
			t.Errorf("forwarded Tailscale-User-Login = %q; want alice@example.com", got)
		}
		if got := res.Header.Get("Echo-User-Email"); got != "alice@example.com" {
			t.Errorf("forwarded Tailscale-User-Email = %q; want alice@example.com", got)
		}
	})

	t.Run("valid session not on allowlist is 403", func(t *testing.T) {
		backendHit = false
		tok := mint(&funnelAuthSession{
			Sub: "u2", Email: "mallory@evil.com", EmailVerified: true,
			FQDN: "example.ts.net", Expiry: now.Add(time.Hour).Unix(),
		})
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, "/private", tok))
		if w.Result().StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d; want 403", w.Result().StatusCode)
		}
		if backendHit {
			t.Error("backend must not be reached for a disallowed user")
		}
	})

	t.Run("expired session bounces", func(t *testing.T) {
		tok := mint(&funnelAuthSession{
			Sub: "u1", Email: "alice@example.com", EmailVerified: true,
			FQDN: "example.ts.net", Expiry: now.Add(-time.Hour).Unix(),
		})
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, "/private", tok))
		if w.Result().StatusCode != http.StatusFound {
			t.Fatalf("status = %d; want 302 (re-auth)", w.Result().StatusCode)
		}
	})

	t.Run("reserved logout path is intercepted, not proxied", func(t *testing.T) {
		backendHit = false
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, funnelAuthLogoutPath, ""))
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("logout status = %d; want 200", res.StatusCode)
		}
		if backendHit {
			t.Error("logout must be handled by the node, not proxied to the app")
		}
		// Logout must clear the session cookie.
		var cleared bool
		for _, c := range res.Cookies() {
			if c.Name == funnelSessionCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Error("logout did not clear the session cookie")
		}
	})

	t.Run("unknown reserved path is 404, never proxied", func(t *testing.T) {
		backendHit = false
		w := httptest.NewRecorder()
		b.serveWebHandler(w, funnelReq(t, funnelAuthReservedPrefix+"sneaky", ""))
		if w.Result().StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d; want 404 for reserved-prefix app route", w.Result().StatusCode)
		}
		if backendHit {
			t.Error("an app route under the reserved prefix must not be reachable")
		}
	})

	t.Run("redirect loop guard returns error, not another bounce", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Came back from a login (loop param set) but still no cookie.
		b.serveWebHandler(w, funnelReq(t, "/private?"+funnelAuthLoopParam+"=1", ""))
		if w.Result().StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d; want 403 (loop guard)", w.Result().StatusCode)
		}
	})
}

// TestFunnelUnauthenticatedUnchanged verifies that a Funnel handler without
// Auth is served exactly as before (no gate, no redirect, backend reached).
func TestFunnelUnauthenticatedUnchanged(t *testing.T) {
	backendHit := false
	testServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		// The funnel request header must still be set; the auth identity
		// headers must not be present for unauthenticated funnel.
		w.Header().Set("Echo-Funnel", r.Header.Get("Tailscale-Funnel-Request"))
		w.Header().Set("Echo-User-Login", r.Header.Get("Tailscale-User-Login"))
	}))
	defer testServ.Close()

	b := newTestBackend(t)
	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"example.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: testServ.URL}, // no Auth
			}},
		},
		AllowFunnel: map[ipn.HostPort]bool{"example.ts.net:443": true},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	b.serveWebHandler(w, funnelReq(t, "/anything", ""))
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", res.StatusCode)
	}
	if !backendHit {
		t.Fatal("backend should be reached directly for unauthenticated funnel")
	}
	if got := res.Header.Get("Echo-Funnel"); got != "?1" {
		t.Errorf("Tailscale-Funnel-Request = %q; want ?1", got)
	}
	if got := res.Header.Get("Echo-User-Login"); got != "" {
		t.Errorf("unauthenticated funnel unexpectedly forwarded identity: %q", got)
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

// TestFunnelCallbackExchangeEndToEnd drives the node-side OIDC callback path in
// process against a stub IdP: token exchange (/api/v2/oauth/token) + JWKS fetch
// (/.well-known/jwks.json) + id_token verification + session-cookie minting.
// This is the "full login loop minus WireGuard/DNS/cert" backup for the
// containerized demo: it proves the callback logic without any tailnet transport
// (the injector's job of physically reaching the node is not exercised here).
func TestFunnelCallbackExchangeEndToEnd(t *testing.T) {
	const fqdn = "example.ts.net"
	const kid = "stub-key-1"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Stub IdP: serves JWKS and a token endpoint that returns a valid id_token.
	var issuer string // set after the server starts (so iss == control URL)
	nonce := "test-nonce-xyz"
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksJSONForKey(t, priv, kid))
		case "/api/v2/oauth/token":
			// A real control validates grant_type/PKCE/client_id here; the stub
			// asserts the essentials and mints the token.
			r.ParseForm()
			if r.Form.Get("grant_type") != "authorization_code" ||
				r.Form.Get("client_id") != funnelAuthClientID ||
				r.Form.Get("code") == "" || r.Form.Get("code_verifier") == "" {
				http.Error(w, "bad token request", http.StatusBadRequest)
				return
			}
			tok := signTestRS256JWT(t, priv, kid, map[string]any{
				"sub": "u-alice", "email": "alice@example.com", "email_verified": true,
				"name": "Alice", "iss": issuer, "aud": fqdn, "nonce": nonce,
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"id_token": tok})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer idp.Close()
	issuer = idp.URL

	b := newTestBackend(t)
	// Point the node's control URL at the stub IdP so funnelAuthControlURL,
	// funnelAuthIssuer, and the JWKS fetch all resolve to it.
	pv := b.pm.CurrentPrefs().AsStruct()
	pv.ControlURL = idp.URL
	if err := b.pm.SetPrefs(pv.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}

	backendHit := false
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.Header().Set("Echo-User-Login", r.Header.Get("Tailscale-User-Login"))
	}))
	defer app.Close()

	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			ipn.HostPort(fqdn + ":443"): {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: app.URL, Auth: &ipn.FunnelAuth{Provider: "tailscale"}},
			}},
		},
		AllowFunnel: map[ipn.HostPort]bool{ipn.HostPort(fqdn + ":443"): true},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}

	keys, err := b.funnelAuthKeys()
	if err != nil {
		t.Fatal(err)
	}
	// Seal a state matching what startFunnelAuthLogin would have produced.
	csrf := "csrf-token-123"
	st := &funnelAuthState{
		OrigURL:      "https://" + fqdn + "/private",
		CodeVerifier: "verifier-abc",
		Nonce:        nonce,
		CSRF:         csrf,
		Expiry:       time.Now().Add(10 * time.Minute).Unix(),
	}
	stateVal, err := keys.sealFunnelState(st, fqdn)
	if err != nil {
		t.Fatal(err)
	}

	// Drive the callback: GET /.well-known/tailscale/funnel-auth/callback?code&state
	// with the matching state cookie.
	req := funnelReq(t, funnelAuthCallbackPath+"?code=authcode123&state="+url.QueryEscape(stateVal), "")
	req.AddCookie(&http.Cookie{Name: funnelStateCookieName, Value: csrf})
	w := httptest.NewRecorder()
	b.serveWebHandler(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d; want 302 to original URL. body=%s", res.StatusCode, w.Body.String())
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "/private") {
		t.Errorf("callback Location = %q; want the original /private URL", loc)
	}
	// The callback must set the session cookie.
	var sessCookie string
	for _, c := range res.Cookies() {
		if c.Name == funnelSessionCookieName {
			sessCookie = c.Value
		}
	}
	if sessCookie == "" {
		t.Fatal("callback did not set a session cookie")
	}

	// That session cookie must now admit a request to the protected app.
	w2 := httptest.NewRecorder()
	b.serveWebHandler(w2, funnelReq(t, "/private", sessCookie))
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("authed request status = %d; want 200", w2.Result().StatusCode)
	}
	if !backendHit {
		t.Error("backend was not reached with the minted session cookie")
	}
	if got := w2.Result().Header.Get("Echo-User-Login"); got != "alice@example.com" {
		t.Errorf("forwarded login = %q; want alice@example.com", got)
	}
}
