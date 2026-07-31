// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/types/key"
)

// Authenticated Funnel session and allowlist primitives.
//
// This file holds the security-sensitive, self-contained pieces of the
// authenticated Funnel gate: deriving the per-node/per-profile cookie key,
// sealing/opening the stateless session cookie, and evaluating the allowlist.
// The gate and OIDC callback that drive these live in funnelauth_gate.go.
//
// The design is stateless by choice (spec §4.1): the visitor's browser holds
// an AEAD-sealed session; the node keeps no server-side session store. The
// sealing key never leaves the device and survives restart because it is
// derived from the node's existing machine private key.

const (
	// funnelSessionCookieName is the browser cookie holding the sealed
	// session for an authenticated Funnel visitor.
	funnelSessionCookieName = "ts_funnel_session"

	// funnelStateCookieName is a short-lived cookie holding the CSRF token
	// for an in-progress login, used to bind the OIDC state to this browser.
	funnelStateCookieName = "ts_funnel_state"

	// funnelDefaultSessionTTL is used when FunnelAuth.SessionTTL is zero.
	// 12h = a workday; re-auth the next day (spec §6.1).
	funnelDefaultSessionTTL = 12 * time.Hour

	// funnelStateTTL bounds how long a login (authorize→callback) may take.
	funnelStateTTL = 10 * time.Minute
)

// funnelAuthSession is the visitor identity carried in the sealed session
// cookie. All fields are set by the node at callback time from a verified
// id_token; the browser cannot forge them (AEAD) and cannot read them
// (opaque ciphertext).
type funnelAuthSession struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"ev,omitempty"`
	Name          string `json:"name,omitempty"`
	Tailnet       string `json:"tn,omitempty"`
	FQDN          string `json:"fqdn"`
	Expiry        int64  `json:"exp"` // unix seconds
}

// expired reports whether the session is at or past its expiry as of now.
func (s *funnelAuthSession) expired(now time.Time) bool {
	return now.Unix() >= s.Expiry
}

// funnelAuthState is the opaque, sealed OIDC "state" carried through the
// login redirect. It lets the callback complete the PKCE exchange statelessly
// and verify the flow it belongs to.
type funnelAuthState struct {
	OrigURL      string `json:"u"` // absolute URL to return to after login
	CodeVerifier string `json:"v"` // PKCE code_verifier
	Nonce        string `json:"n"` // id_token nonce, echoed by control
	CSRF         string `json:"c"` // double-submit token; must match state cookie
	Expiry       int64  `json:"exp"`
}

// funnelAuthKeys are the AEAD keys used to seal Funnel auth material. They are
// derived from the node's machine private key so they are per-node, persistent
// across restarts, and never leave the device.
type funnelAuthKeys struct {
	session cipher.AEAD // seals the long-lived session cookie
	state   cipher.AEAD // seals the short-lived login state
}

// funnelAuthKeys derives the AEAD keys for the current profile. The key
// material is HKDF(machine-private-key, salt=profileID, info=purpose), so
// different profiles and different purposes get independent keys, and rotating
// the machine key (re-login) invalidates old sessions.
func (b *LocalBackend) funnelAuthKeys() (*funnelAuthKeys, error) {
	mk, err := b.machinePrivKeyForFunnelAuth()
	if err != nil {
		return nil, err
	}
	if mk.IsZero() {
		return nil, errors.New("no machine key available for funnel auth")
	}
	profileID := string(b.CurrentProfile().ID())
	secret := mk.UntypedBytes()
	salt := []byte("tailscale-funnel-auth:" + profileID)

	sessAEAD, err := deriveFunnelAEAD(secret, salt, "session-cookie-v1")
	if err != nil {
		return nil, err
	}
	stateAEAD, err := deriveFunnelAEAD(secret, salt, "login-state-v1")
	if err != nil {
		return nil, err
	}
	return &funnelAuthKeys{session: sessAEAD, state: stateAEAD}, nil
}

// machinePrivKeyForFunnelAuth returns the node's machine private key,
// initializing it if necessary. It is used only as HKDF input; the key itself
// is never transmitted.
func (b *LocalBackend) machinePrivKeyForFunnelAuth() (key.MachinePrivate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.initMachineKeyLocked(); err != nil {
		return key.MachinePrivate{}, err
	}
	return b.machinePrivKey, nil
}

// deriveFunnelAEAD derives a 256-bit AES-GCM AEAD from secret via HKDF-SHA256.
func deriveFunnelAEAD(secret, salt []byte, info string) (cipher.AEAD, error) {
	dk, err := hkdf.Key(sha256.New, secret, salt, "tailscale-funnel-auth:"+info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealFunnelValue AEAD-seals v and returns a base64url (raw, unpadded) token.
// aad binds the ciphertext to a context (the funnel FQDN) so a cookie minted
// for one funnel host cannot be replayed against another.
func sealFunnelValue(aead cipher.AEAD, v any, aad string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, plain, []byte(aad))
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// openFunnelValue reverses sealFunnelValue into dst. It returns an error if the
// token is malformed, was sealed with a different key, or has a different aad.
func openFunnelValue(aead cipher.AEAD, token, aad string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return errors.New("funnel token too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := aead.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return err // authentication failed: tampered, wrong key, or wrong host
	}
	return json.Unmarshal(plain, dst)
}

// sealFunnelSession seals s for the browser cookie, binding it to s.FQDN.
func (k *funnelAuthKeys) sealFunnelSession(s *funnelAuthSession) (string, error) {
	return sealFunnelValue(k.session, s, s.FQDN)
}

// openFunnelSession opens a session cookie value and verifies it is bound to
// fqdn and not expired as of now. A non-nil error means the caller must treat
// the visitor as unauthenticated.
func (k *funnelAuthKeys) openFunnelSession(token, fqdn string, now time.Time) (*funnelAuthSession, error) {
	var s funnelAuthSession
	if err := openFunnelValue(k.session, token, fqdn, &s); err != nil {
		return nil, err
	}
	if s.FQDN != fqdn {
		return nil, fmt.Errorf("session host %q != request host %q", s.FQDN, fqdn)
	}
	if s.expired(now) {
		return nil, errors.New("session expired")
	}
	return &s, nil
}

// sealFunnelState seals st for the OIDC state parameter, bound to fqdn.
func (k *funnelAuthKeys) sealFunnelState(st *funnelAuthState, fqdn string) (string, error) {
	return sealFunnelValue(k.state, st, fqdn)
}

// openFunnelState opens an OIDC state value, verifying it is bound to fqdn and
// not expired.
func (k *funnelAuthKeys) openFunnelState(token, fqdn string, now time.Time) (*funnelAuthState, error) {
	var st funnelAuthState
	if err := openFunnelValue(k.state, token, fqdn, &st); err != nil {
		return nil, err
	}
	if now.Unix() >= st.Expiry {
		return nil, errors.New("login state expired")
	}
	return &st, nil
}

// funnelAuthAllowed reports whether the given verified identity satisfies the
// allowlist. An empty allowlist admits any authenticated Tailscale user
// (spec §4.2). Otherwise the identity must match at least one entry:
//
//   - "alice@example.com"   exact email (email_verified not required)
//   - "*@example.com"       email domain, only if email_verified and the
//     domain is a real email domain (not an emailish value like "alice@github")
//   - "tailnet:example.com" the id_token tailnet claim
//
// It is evaluated on every request (data comes from the cookie) so tightening
// the allowlist takes effect on the next request within a live session.
func funnelAuthAllowed(allow []string, email string, emailVerified bool, tailnet string) bool {
	if len(allow) == 0 {
		return true
	}
	email = strings.ToLower(strings.TrimSpace(email))
	dom := emailDomain(email)
	for _, raw := range allow {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		switch {
		case strings.HasPrefix(e, "tailnet:"):
			want := strings.TrimPrefix(e, "tailnet:")
			if tailnet != "" && strings.EqualFold(tailnet, want) {
				return true
			}
		case strings.HasPrefix(e, "*@"):
			want := strings.ToLower(strings.TrimPrefix(e, "*@"))
			if emailVerified && isRealEmailDomain(want) && dom != "" && dom == want {
				return true
			}
		default:
			if email != "" && strings.EqualFold(email, e) {
				return true
			}
		}
	}
	return false
}

// emailDomain returns the lowercased domain part of an email address, or "" if
// there is no "@" separator.
func emailDomain(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 || i == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}

// isRealEmailDomain reports whether dom looks like a real, routable email
// domain (has a dot, no "@"), as opposed to an emailish value such as the
// "@github" style login handles that some IdPs emit. Domain-wildcard
// allowlist entries only match real domains (cross-repo contract §"email_verified
// trust rule").
func isRealEmailDomain(dom string) bool {
	return dom != "" && strings.Contains(dom, ".") && !strings.Contains(dom, "@")
}

// newFunnelRandomToken returns a URL-safe random token with n bytes of entropy.
func newFunnelRandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
