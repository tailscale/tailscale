// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/ipn"
)

// Authenticated Funnel gate and OIDC callback (spec §3).
//
// This file is the security boundary: it decides whether a Funnel request is
// admitted, runs the Login With Tailscale OIDC exchange, and passes the
// verified identity to the backend. The unauthenticated Funnel path is
// unchanged: nothing here runs unless the matched handler has Auth != nil and
// the request arrived over Funnel.

const (
	// funnelAuthReservedPrefix is intercepted before any user mount point so
	// the OIDC callback and logout endpoints can never collide with, or be
	// shadowed by, an app route. See serveWebHandler.
	funnelAuthReservedPrefix = "/.well-known/tailscale/funnel-auth/"
	funnelAuthCallbackPath   = funnelAuthReservedPrefix + "callback"
	funnelAuthLogoutPath     = funnelAuthReservedPrefix + "logout"

	// funnelAuthClientID is the shared first-party OIDC client id (cross-repo
	// contract §"Client identity"). Public client, no secret.
	funnelAuthClientID = "tailscale-funnel"

	// funnelAuthLoopParam is set on the redirect back to the app after a
	// successful login. If the gate then still finds no valid session it
	// serves an error instead of bouncing again, guarding against a redirect
	// loop (e.g. a browser refusing our cookie).
	funnelAuthLoopParam = "ts_funnel_authed"
)

// handleFunnelAuthReserved serves the reserved /.well-known/tailscale/funnel-auth/*
// endpoints. It is called from serveWebHandler before mount-point matching, but
// only for Funnel requests to a handler that has Auth configured. It reports
// whether it handled the request; if false, normal serving continues.
func (b *LocalBackend) handleFunnelAuthReserved(w http.ResponseWriter, r *http.Request, auth ipn.FunnelAuthView) bool {
	switch r.URL.Path {
	case funnelAuthCallbackPath:
		b.serveFunnelAuthCallback(w, r, auth)
		return true
	case funnelAuthLogoutPath:
		b.serveFunnelAuthLogout(w, r)
		return true
	}
	// Any other path under the reserved prefix is ours (never the app's);
	// refuse it rather than leaking it to the backend.
	if strings.HasPrefix(r.URL.Path, funnelAuthReservedPrefix) {
		http.NotFound(w, r)
		return true
	}
	return false
}

// funnelAuthGate enforces authentication for a Funnel request to an
// Auth-configured handler. It reports whether the request is allowed to
// proceed to normal serving. When it returns false it has already written a
// response (a 302 to Login With Tailscale, or an error page).
func (b *LocalBackend) funnelAuthGate(w http.ResponseWriter, r *http.Request, auth ipn.FunnelAuthView) (allow bool) {
	fqdn := funnelRequestFQDN(r)
	keys, err := b.funnelAuthKeys()
	if err != nil {
		b.logf("funnelauth: cannot derive keys: %v", err)
		http.Error(w, "authentication is temporarily unavailable", http.StatusServiceUnavailable)
		return false
	}

	// Valid existing session → evaluate the (live) allowlist and continue.
	if c, err := r.Cookie(funnelSessionCookieName); err == nil {
		if sess, err := keys.openFunnelSession(c.Value, fqdn, time.Now()); err == nil {
			if !funnelAuthAllowed(auth.Allow().AsSlice(), sess.Email, sess.EmailVerified, sess.Tailnet) {
				b.serveFunnelAuthForbidden(w, r)
				return false
			}
			// Stash the identity so addTailscaleIdentityHeaders can forward it.
			if sc, ok := serveHTTPContextKey.ValueOk(r.Context()); ok {
				sc.FunnelAuthSession = sess
			}
			return true
		}
	}

	// No valid session. If we *just* came back from a successful login and
	// still have no cookie, don't bounce again: that's a redirect loop.
	if r.URL.Query().Get(funnelAuthLoopParam) != "" {
		http.Error(w, "Sign-in did not complete. Your browser may be blocking cookies for this site.", http.StatusForbidden)
		return false
	}

	b.startFunnelAuthLogin(w, r, keys, fqdn)
	return false
}

// startFunnelAuthLogin builds the PKCE authorize request, stores the login
// state in a sealed cookie, and 302s the browser to control.
func (b *LocalBackend) startFunnelAuthLogin(w http.ResponseWriter, r *http.Request, keys *funnelAuthKeys, fqdn string) {
	verifier, err := newFunnelRandomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := newFunnelRandomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := newFunnelRandomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	st := &funnelAuthState{
		OrigURL:      funnelRequestURL(r, fqdn),
		CodeVerifier: verifier,
		Nonce:        nonce,
		CSRF:         csrf,
		Expiry:       now.Add(funnelStateTTL).Unix(),
	}
	stateVal, err := keys.sealFunnelState(st, fqdn)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The CSRF token is double-submitted: it lives in both the sealed state
	// (carried by control) and this host-only cookie (carried by the browser).
	// The callback requires them to match, so a state minted for one browser
	// cannot be replayed by an attacker in another.
	http.SetCookie(w, &http.Cookie{
		Name:     funnelStateCookieName,
		Value:    csrf,
		Path:     funnelAuthReservedPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(funnelStateTTL / time.Second),
	})

	redirectURI := "https://" + fqdn + funnelAuthCallbackPath
	challenge := funnelPKCEChallenge(verifier)

	authorize := b.funnelAuthControlURL("/a/oauth_authorize")
	q := url.Values{}
	q.Set("client_id", funnelAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email")
	q.Set("state", stateVal)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authorize += "?" + q.Encode()

	http.Redirect(w, r, authorize, http.StatusFound)
}

// serveFunnelAuthCallback completes the OIDC exchange and issues a session.
func (b *LocalBackend) serveFunnelAuthCallback(w http.ResponseWriter, r *http.Request, auth ipn.FunnelAuthView) {
	fqdn := funnelRequestFQDN(r)
	keys, err := b.funnelAuthKeys()
	if err != nil {
		http.Error(w, "authentication is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now()

	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "Sign-in failed: "+funnelSafeText(errParam), http.StatusForbidden)
		return
	}
	code := q.Get("code")
	stateVal := q.Get("state")
	if code == "" || stateVal == "" {
		http.Error(w, "invalid callback request", http.StatusBadRequest)
		return
	}

	st, err := keys.openFunnelState(stateVal, fqdn, now)
	if err != nil {
		http.Error(w, "invalid or expired sign-in state", http.StatusBadRequest)
		return
	}
	// CSRF: the state's token must match the browser's state cookie.
	sc, err := r.Cookie(funnelStateCookieName)
	if err != nil || sc.Value == "" || sc.Value != st.CSRF {
		http.Error(w, "sign-in state mismatch", http.StatusBadRequest)
		return
	}

	redirectURI := "https://" + fqdn + funnelAuthCallbackPath
	idToken, err := b.funnelAuthExchangeCode(r.Context(), code, st.CodeVerifier, redirectURI)
	if err != nil {
		b.logf("funnelauth: token exchange failed: %v", err)
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}

	claims, err := b.funnelAuthVerifyIDToken(r.Context(), idToken, fqdn, st.Nonce, now)
	if err != nil {
		b.logf("funnelauth: id_token verification failed: %v", err)
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}

	if !funnelAuthAllowed(auth.Allow().AsSlice(), claims.Email, claims.EmailVerified, claims.Tailnet) {
		b.serveFunnelAuthForbidden(w, r)
		return
	}

	ttl := auth.SessionTTL()
	if ttl <= 0 {
		ttl = funnelDefaultSessionTTL
	}
	sess := &funnelAuthSession{
		Sub:           claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Tailnet:       claims.Tailnet,
		FQDN:          fqdn,
		Expiry:        now.Add(ttl).Unix(),
	}
	sealed, err := keys.sealFunnelSession(sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     funnelSessionCookieName,
		Value:    sealed,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl / time.Second),
	})
	// Clear the now-consumed login-state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     funnelStateCookieName,
		Value:    "",
		Path:     funnelAuthReservedPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Return to the originally requested URL, tagging it so the gate can
	// detect a cookie-rejecting browser instead of looping.
	dest := funnelAuthAppendLoopParam(st.OrigURL, fqdn)
	http.Redirect(w, r, dest, http.StatusFound)
}

// serveFunnelAuthLogout clears the session cookie and shows a short message.
func (b *LocalBackend) serveFunnelAuthLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     funnelSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "You have been signed out.\n")
}

func (b *LocalBackend) serveFunnelAuthForbidden(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, "This app is restricted and your Tailscale account is not on its allowlist.\n")
}

// funnelAuthIDTokenClaims are the claims tailscaled verifies from the id_token
// (cross-repo contract §"id_token claims"). aud is decoded permissively because
// OIDC allows it to be either a string or an array of strings.
type funnelAuthIDTokenClaims struct {
	Subject       string        `json:"sub"`
	Email         string        `json:"email"`
	EmailVerified bool          `json:"email_verified"`
	Name          string        `json:"name"`
	Tailnet       string        `json:"tailnet"`
	Nonce         string        `json:"nonce"`
	Issuer        string        `json:"iss"`
	Audience      audienceClaim `json:"aud"`
	Expiry        int64         `json:"exp"`
	NotBefore     int64         `json:"nbf"`
	IssuedAt      int64         `json:"iat"`
}

// audienceClaim decodes the OIDC "aud" claim, which may be a single string or
// an array of strings.
type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audienceClaim{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audienceClaim) contains(want string) bool {
	for _, s := range a {
		if s == want {
			return true
		}
	}
	return false
}

// funnelAuthExchangeCode POSTs the authorization code to control's token
// endpoint and returns the raw id_token JWT (cross-repo contract §"Token
// request"/"Token response").
func (b *LocalBackend) funnelAuthExchangeCode(ctx context.Context, code, verifier, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("client_id", funnelAuthClientID)
	form.Set("redirect_uri", redirectURI)

	tokenURL := b.funnelAuthControlURL("/api/v2/oauth/token")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.funnelAuthHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, body)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("token response missing id_token")
	}
	return tr.IDToken, nil
}

// funnelAuthLeeway is the clock-skew tolerance applied to id_token time claims.
const funnelAuthLeeway = time.Minute

// funnelAuthVerifyIDToken verifies the id_token's RS256 signature against
// control's JWKS and checks iss, aud (== this node's FQDN, the anti-replay
// binding), nonce, and exp/nbf. It returns the parsed claims on success.
//
// It deliberately implements the JWS check with the standard library and
// hard-codes RS256, both to avoid pulling a JWT module into tailscaled's
// dependency graph and to eliminate algorithm-confusion attacks (an attacker
// cannot downgrade the token to "none" or an HMAC alg keyed on the public key).
func (b *LocalBackend) funnelAuthVerifyIDToken(ctx context.Context, idToken, fqdn, wantNonce string, now time.Time) (*funnelAuthIDTokenClaims, error) {
	hdr, payload, err := verifyRS256JWT(idToken, func(kid string) (*rsa.PublicKey, error) {
		return b.funnelAuthSigningKey(ctx, kid)
	})
	if err != nil {
		return nil, err
	}
	_ = hdr

	var claims funnelAuthIDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decoding id_token claims: %w", err)
	}

	if want := b.funnelAuthIssuer(); claims.Issuer != want {
		return nil, fmt.Errorf("id_token issuer %q != %q", claims.Issuer, want)
	}
	// aud must equal this node's FQDN (cross-repo contract §"FQDN binding").
	// This is the cross-host anti-replay binding.
	if !claims.Audience.contains(fqdn) {
		return nil, fmt.Errorf("id_token audience %v does not include %q", []string(claims.Audience), fqdn)
	}
	if claims.Nonce != wantNonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}
	if claims.Expiry == 0 || now.Add(-funnelAuthLeeway).Unix() >= claims.Expiry {
		return nil, fmt.Errorf("id_token expired")
	}
	if claims.NotBefore != 0 && now.Add(funnelAuthLeeway).Unix() < claims.NotBefore {
		return nil, fmt.Errorf("id_token not yet valid")
	}
	return &claims, nil
}

// verifyRS256JWT parses a compact JWS, requires alg RS256, looks up the signing
// key by the header kid, verifies the signature, and returns the raw header and
// payload JSON. keyFn resolves a kid to an RSA public key.
func verifyRS256JWT(token string, keyFn func(kid string) (*rsa.PublicKey, error)) (header, payload []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("malformed JWT: want 3 parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, nil, fmt.Errorf("unsupported JWT alg %q; want RS256", hdr.Alg)
	}
	pub, err := keyFn(hdr.Kid)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving signing key %q: %w", hdr.Kid, err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT signature: %w", err)
	}
	signing := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signing))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}
	return headerJSON, payloadJSON, nil
}

// funnelAuthControlURL returns an absolute control URL for the given path,
// using the current profile's control server.
func (b *LocalBackend) funnelAuthControlURL(path string) string {
	base := strings.TrimRight(b.Prefs().ControlURLOrDefault(b.polc), "/")
	return base + path
}

// funnelAuthIssuer returns the expected id_token issuer, which is control's
// base URL (cross-repo contract: iss = control server URL).
func (b *LocalBackend) funnelAuthIssuer() string {
	return strings.TrimRight(b.Prefs().ControlURLOrDefault(b.polc), "/")
}

// funnelAuthHTTPClient returns an HTTP client that dials via the node's system
// dialer, matching how tailscaled otherwise reaches control.
func (b *LocalBackend) funnelAuthHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           b.dialer.SystemDial,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

const funnelJWKSTTL = time.Hour

// funnelAuthSigningKey returns the RSA public key with the given kid from
// control's JWKS, fetching and caching the key set as needed. If the kid is not
// found in the cached set, it refetches once (control may have rotated keys).
func (b *LocalBackend) funnelAuthSigningKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, err := b.funnelAuthJWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	if pub, ok := keys[kid]; ok {
		return pub, nil
	}
	// Unknown kid: force a refresh in case control rotated its keys.
	keys, err = b.funnelAuthJWKS(ctx, true)
	if err != nil {
		return nil, err
	}
	if pub, ok := keys[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("no signing key with kid %q", kid)
}

// funnelAuthJWKS returns control's RSA signing keys, keyed by kid, fetching and
// caching the JWKS as needed. forceRefresh bypasses the cache. The cache stores
// raw JSON (b.funnelJWKS uses stdlib-only field types so the ts_omit_serve
// build still compiles); this serve-only code parses it on use.
func (b *LocalBackend) funnelAuthJWKS(ctx context.Context, forceRefresh bool) (map[string]*rsa.PublicKey, error) {
	jwksURL := b.funnelAuthControlURL("/.well-known/jwks.json")
	c := &b.funnelJWKS

	if !forceRefresh {
		c.mu.Lock()
		fresh := c.raw != nil && c.url == jwksURL && time.Since(c.fetched) < funnelJWKSTTL
		raw := c.raw
		c.mu.Unlock()
		if fresh {
			return parseJWKS(raw)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.funnelAuthHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS status %d", resp.StatusCode)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.raw = body
	c.fetched = time.Now()
	c.url = jwksURL
	c.mu.Unlock()
	return keys, nil
}

// jwksKey is a single RSA JWK (RFC 7517 §4, RFC 7518 §6.3.1).
type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // base64url big-endian modulus
	E   string `json:"e"` // base64url big-endian exponent
}

// parseJWKS decodes a JWKS document into a map of kid → RSA public key. Only
// RSA keys are retained (control mints RS256 id_tokens).
func parseJWKS(raw []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []jwksKey `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}
	out := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k)
		if err != nil {
			return nil, fmt.Errorf("parsing JWK %q: %w", k.Kid, err)
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("JWKS contained no RSA keys")
	}
	return out, nil
}

// rsaPublicKeyFromJWK builds an *rsa.PublicKey from a JWK's base64url n and e.
func rsaPublicKeyFromJWK(k jwksKey) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	// Left-pad the exponent to 8 bytes to read as a uint64.
	var eBuf [8]byte
	copy(eBuf[8-len(eb):], eb)
	e := binary.BigEndian.Uint64(eBuf[:])
	if e == 0 || e > 1<<31 {
		return nil, fmt.Errorf("invalid exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(e),
	}, nil
}

// funnelPKCEChallenge returns BASE64URL(SHA256(verifier)) (RFC 7636 S256).
func funnelPKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// funnelRequestFQDN returns the funnel host for this request, stripping any
// port. For Funnel requests this is the SNI/Host the visitor connected to,
// which is the node's MagicDNS FQDN.
func funnelRequestFQDN(r *http.Request) string {
	host := r.Host
	if r.TLS != nil && r.TLS.ServerName != "" {
		host = r.TLS.ServerName
	}
	if h, _, err := splitHostMaybePort(host); err == nil {
		host = h
	}
	return host
}

// funnelRequestURL reconstructs the absolute https URL the visitor requested,
// used as the post-login return target. The host is forced to the funnel FQDN
// (never taken from an attacker-influenced Host header target) so it can only
// point back at this node — closing the open-redirect surface.
func funnelRequestURL(r *http.Request, fqdn string) string {
	u := &url.URL{
		Scheme:   "https",
		Host:     fqdn,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	return u.String()
}

// funnelAuthAppendLoopParam adds the redirect-loop guard marker to dest,
// re-forcing the host to fqdn so a tampered state URL can never redirect off
// this node.
func funnelAuthAppendLoopParam(dest, fqdn string) string {
	u, err := url.Parse(dest)
	if err != nil || u.Host != fqdn || u.Scheme != "https" {
		u = &url.URL{Scheme: "https", Host: fqdn, Path: "/"}
	}
	q := u.Query()
	q.Set(funnelAuthLoopParam, "1")
	u.RawQuery = q.Encode()
	return u.String()
}

// funnelSafeText trims and truncates untrusted text for inclusion in an error
// page, and strips characters that could confuse a text/plain response.
func funnelSafeText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// splitHostMaybePort splits host:port, tolerating a bare host with no port.
func splitHostMaybePort(hostport string) (host, port string, err error) {
	if !strings.Contains(hostport, ":") {
		return hostport, "", nil
	}
	return net.SplitHostPort(hostport)
}
