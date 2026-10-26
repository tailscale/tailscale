// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// serveCheckPathPrefix is where tailscaled serves its own step-up page and
// WebAuthn endpoints, on the same host as the handler being checked.
const serveCheckPathPrefix = "/.tailscale/check/"

const defaultServeCheckPeriod = 12 * time.Hour

// serveCheckChallengeTTL is how long a WebAuthn challenge stays usable.
const serveCheckChallengeTTL = 2 * time.Minute

// serveCheckCredsKey is the state store key holding the enrolled WebAuthn
// credentials, by user.
const serveCheckCredsKey ipn.StateKey = "_serve-check-credentials"

// serveCheckKey identifies one (peer node, handler) pair. Each pair has its
// own check timer.
type serveCheckKey struct {
	node   tailcfg.StableNodeID
	target string // "[svc:name|]host:port/mount"
}

type serveCheckChallenge struct {
	key      serveCheckKey
	user     tailcfg.UserID
	register bool
	expires  time.Time
}

// serveCheckCred is an enrolled WebAuthn credential.
type serveCheckCred struct {
	ID        []byte // credential ID
	PublicKey []byte // PKIX (SubjectPublicKeyInfo) DER
	SignCount uint32
	Created   time.Time
}

// serveCheckState holds the step-up check state for serve handlers with
// [ipn.HTTPHandler.Check] set. The zero value is ready to use.
type serveCheckState struct {
	mu         sync.Mutex
	checked    map[serveCheckKey]time.Time // last successful check
	challenges map[string]*serveCheckChallenge
	creds      map[tailcfg.UserID][]*serveCheckCred // nil until loaded from the store
}

// serveCheckPeer returns the peer key for a checked handler at mount, or an
// error if the request can't be checked at all (funnel, tagged or unknown
// peers have no user to prove presence).
func (b *LocalBackend) serveCheckPeer(r *http.Request, mount string) (serveCheckKey, tailcfg.NodeView, tailcfg.UserProfile, error) {
	sctx, ok := serveHTTPContextKey.ValueOk(r.Context())
	if !ok || sctx.Funnel != nil {
		return serveCheckKey{}, tailcfg.NodeView{}, tailcfg.UserProfile{}, errors.New("this page requires a check from a tailnet device")
	}
	node, user, ok := b.WhoIs("tcp", sctx.SrcAddr)
	if !ok {
		return serveCheckKey{}, tailcfg.NodeView{}, tailcfg.UserProfile{}, errors.New("unknown peer")
	}
	if node.IsTagged() {
		return serveCheckKey{}, tailcfg.NodeView{}, tailcfg.UserProfile{}, errors.New("this page requires a check, which tagged devices can't do")
	}
	target := fmt.Sprintf("%s:%d%s", b.serveRequestHostname(r), sctx.DestPort, mount)
	if sctx.ForVIPService != "" {
		target = sctx.ForVIPService.String() + "|" + target
	}
	return serveCheckKey{node: node.StableID(), target: target}, node, user, nil
}

func serveCheckPeriod(h ipn.HTTPHandlerView) time.Duration {
	if d := h.CheckPeriod().Duration; d > 0 {
		return d
	}
	return defaultServeCheckPeriod
}

// serveCheckPassed reports whether the request's peer has a valid check for
// the handler h at mount. If not, it has already written a response: a
// redirect to the step-up page for browser navigations, a 403 otherwise.
func (b *LocalBackend) serveCheckPassed(w http.ResponseWriter, r *http.Request, h ipn.HTTPHandlerView, mount string) bool {
	key, _, _, err := b.serveCheckPeer(r, mount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return false
	}
	now := b.clock.Now()
	s := &b.serveCheck
	s.mu.Lock()
	last, ok := s.checked[key]
	s.mu.Unlock()
	if ok && now.Sub(last) < serveCheckPeriod(h) {
		return true
	}
	stepUp := serveCheckPathPrefix + "?" + url.Values{
		"m":    {mount},
		"next": {r.URL.RequestURI()},
	}.Encode()
	if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, stepUp, http.StatusSeeOther)
		return false
	}
	http.Error(w, "this device needs a security key check first; open "+stepUp+" in a browser", http.StatusForbidden)
	return false
}

// serveCheckHandlerAt returns the handler mounted exactly at mount for r's
// host, if it requires a check.
func (b *LocalBackend) serveCheckHandlerAt(r *http.Request, mount string) (ipn.HTTPHandlerView, bool) {
	if !strings.HasPrefix(mount, "/") {
		return ipn.HTTPHandlerView{}, false
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = mount
	h, at, ok := b.getServeHandler(r2)
	if !ok || at != mount || !h.Check() {
		return ipn.HTTPHandlerView{}, false
	}
	return h, true
}

//go:embed servecheck.html
var serveCheckPageHTML string

var serveCheckPage = template.Must(template.New("check").Parse(serveCheckPageHTML))

// serveCheckEndpoint handles requests under [serveCheckPathPrefix]. It
// reports false, having written nothing, if the request isn't for a checked
// handler on this host, so the path still reaches the app otherwise.
func (b *LocalBackend) serveCheckEndpoint(w http.ResponseWriter, r *http.Request) bool {
	mount := r.URL.Query().Get("m")
	h, ok := b.serveCheckHandlerAt(r, mount)
	if !ok {
		return false
	}
	key, node, user, err := b.serveCheckPeer(r, mount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return true
	}
	switch op := strings.TrimPrefix(r.URL.Path, serveCheckPathPrefix); {
	case op == "" && r.Method == "GET":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		serveCheckPage.Execute(w, map[string]any{
			"Device": node.ComputedName(),
			"User":   user.LoginName,
			"Target": key.target,
			"Period": serveCheckPeriod(h).String(),
		})
	case op == "begin" && r.Method == "POST":
		b.serveCheckBegin(w, r, key, user)
	case op == "finish" && r.Method == "POST":
		b.serveCheckFinish(w, r, key, user)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

var b64 = base64.RawURLEncoding

// serveCheckRPID returns the WebAuthn relying party ID for r: the serve
// hostname, so a passkey is scoped to the name the browser shows.
func (b *LocalBackend) serveCheckRPID(r *http.Request) string {
	return strings.TrimSuffix(b.serveRequestHostname(r), ".")
}

func (b *LocalBackend) serveCheckBegin(w http.ResponseWriter, r *http.Request, key serveCheckKey, user tailcfg.UserProfile) {
	creds, err := b.serveCheckCreds(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ch := make([]byte, 32)
	rand.Read(ch)
	chs := b64.EncodeToString(ch)
	now := b.clock.Now()

	s := &b.serveCheck
	s.mu.Lock()
	for k, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, k)
		}
	}
	if s.challenges == nil {
		s.challenges = make(map[string]*serveCheckChallenge)
	}
	s.challenges[chs] = &serveCheckChallenge{
		key:      key,
		user:     user.ID,
		register: len(creds) == 0,
		expires:  now.Add(serveCheckChallengeTTL),
	}
	s.mu.Unlock()

	var allow []string
	for _, c := range creds {
		allow = append(allow, b64.EncodeToString(c.ID))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"register":    len(creds) == 0,
		"challenge":   chs,
		"rpId":        b.serveCheckRPID(r),
		"userId":      b64.EncodeToString(strconv.AppendInt(nil, int64(user.ID), 10)),
		"userName":    user.LoginName,
		"displayName": user.DisplayName,
		"allow":       allow,
	})
}

// serveCheckFinishRequest is the step-up page's WebAuthn result. All byte
// fields are base64url without padding.
type serveCheckFinishRequest struct {
	Challenge         string
	CredentialID      string
	ClientDataJSON    string
	AuthenticatorData string
	Signature         string // assertions only
	PublicKey         string // registrations only: PKIX DER from getPublicKey()
}

func (b *LocalBackend) serveCheckFinish(w http.ResponseWriter, r *http.Request, key serveCheckKey, user tailcfg.UserProfile) {
	var req serveCheckFinishRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := b.clock.Now()
	s := &b.serveCheck
	s.mu.Lock()
	ch, ok := s.challenges[req.Challenge]
	delete(s.challenges, req.Challenge)
	s.mu.Unlock()
	if !ok || now.After(ch.expires) || ch.key != key || ch.user != user.ID {
		http.Error(w, "unknown or expired challenge; reload the page", http.StatusForbidden)
		return
	}
	if err := b.serveCheckVerify(r, ch, &req); err != nil {
		b.logf("serve: check for %v on %q failed: %v", key.node, key.target, err)
		http.Error(w, "check failed: "+err.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	if s.checked == nil {
		s.checked = make(map[serveCheckKey]time.Time)
	}
	s.checked[key] = now
	s.mu.Unlock()
	b.logf("serve: check passed for %v (%s) on %q", key.node, user.LoginName, key.target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// clientData is the part of WebAuthn's CollectedClientData we check.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// serveCheckVerify verifies a WebAuthn registration (attestation "none") or
// assertion against ch, and stores the credential or its new sign count.
func (b *LocalBackend) serveCheckVerify(r *http.Request, ch *serveCheckChallenge, req *serveCheckFinishRequest) error {
	cdj, err1 := b64.DecodeString(req.ClientDataJSON)
	ad, err2 := b64.DecodeString(req.AuthenticatorData)
	credID, err3 := b64.DecodeString(req.CredentialID)
	if err := errors.Join(err1, err2, err3); err != nil {
		return errors.New("bad encoding")
	}
	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return errors.New("bad client data")
	}
	wantType := "webauthn.get"
	if ch.register {
		wantType = "webauthn.create"
	}
	rpID := b.serveCheckRPID(r)
	if cd.Type != wantType || cd.Challenge != req.Challenge || cd.CrossOrigin {
		return errors.New("client data mismatch")
	}
	if u, err := url.Parse(cd.Origin); err != nil || u.Scheme != "https" || u.Hostname() != rpID {
		return fmt.Errorf("origin %q is not for %q", cd.Origin, rpID)
	}
	// authenticatorData: rpIdHash[32] flags[1] signCount[4] ...
	if len(ad) < 37 {
		return errors.New("short authenticator data")
	}
	if rph := sha256.Sum256([]byte(rpID)); !bytes.Equal(ad[:32], rph[:]) {
		return errors.New("authenticator data is for another relying party")
	}
	const flagUserPresent = 0x01
	if ad[32]&flagUserPresent == 0 {
		return errors.New("user presence not asserted")
	}
	signCount := binary.BigEndian.Uint32(ad[33:37])

	s := &b.serveCheck
	if ch.register {
		pkDER, err := b64.DecodeString(req.PublicKey)
		if err != nil {
			return errors.New("bad public key encoding")
		}
		if _, err := parseServeCheckKey(pkDER); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// TODO: enrolment is trust-on-first-use per user on this node; see DESIGN.md.
		if len(s.creds[ch.user]) > 0 {
			return errors.New("a security key is already enrolled for this user")
		}
		s.creds[ch.user] = append(s.creds[ch.user], &serveCheckCred{
			ID:        credID,
			PublicKey: pkDER,
			SignCount: signCount,
			Created:   b.clock.Now(),
		})
		return b.saveServeCheckCredsLocked()
	}

	sig, err := b64.DecodeString(req.Signature)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var cred *serveCheckCred
	for _, c := range s.creds[ch.user] {
		if bytes.Equal(c.ID, credID) {
			cred = c
		}
	}
	if cred == nil {
		return errors.New("unknown credential")
	}
	pub, err := parseServeCheckKey(cred.PublicKey)
	if err != nil {
		return err
	}
	cdh := sha256.Sum256(cdj)
	signed := append(append([]byte(nil), ad...), cdh[:]...)
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, d[:], sig) {
			return errors.New("bad signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, sig) {
			return errors.New("bad signature")
		}
	}
	if signCount != 0 && signCount <= cred.SignCount {
		return errors.New("sign count went backwards; the key may be cloned")
	}
	if signCount == cred.SignCount {
		return nil
	}
	cred.SignCount = signCount
	return b.saveServeCheckCredsLocked()
}

// parseServeCheckKey parses a credential public key, accepting the ES256
// (P-256) and EdDSA (Ed25519) algorithms the step-up page asks for.
func parseServeCheckKey(der []byte) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("bad public key")
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().Name != "P-256" {
			return nil, errors.New("unsupported curve")
		}
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}
	return pub, nil
}

// serveCheckCreds returns the credentials enrolled for uid, loading them from
// the state store on first use.
func (b *LocalBackend) serveCheckCreds(uid tailcfg.UserID) ([]*serveCheckCred, error) {
	s := &b.serveCheck
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.creds == nil {
		s.creds = make(map[tailcfg.UserID][]*serveCheckCred)
		bs, err := b.store.ReadState(serveCheckCredsKey)
		if err != nil && !errors.Is(err, ipn.ErrStateNotExist) {
			s.creds = nil
			return nil, err
		}
		if len(bs) > 0 {
			if err := json.Unmarshal(bs, &s.creds); err != nil {
				s.creds = nil
				return nil, err
			}
		}
	}
	return s.creds[uid], nil
}

// s.mu must be held.
func (b *LocalBackend) saveServeCheckCredsLocked() error {
	bs, err := json.Marshal(b.serveCheck.creds)
	if err != nil {
		return err
	}
	return b.store.WriteState(serveCheckCredsKey, bs)
}
