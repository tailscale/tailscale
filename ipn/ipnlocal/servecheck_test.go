// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/netmap"
)

// softKey is a software WebAuthn authenticator for one relying party.
type softKey struct {
	t     *testing.T
	priv  *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftKey(t *testing.T) *softKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &softKey{t: t, priv: priv, id: []byte("cred-" + t.Name())}
}

func (k *softKey) authData(rpID string) []byte {
	k.count++
	rph := sha256.Sum256([]byte(rpID))
	ad := append(rph[:], 0x01) // user present
	return binary.BigEndian.AppendUint32(ad, k.count)
}

func clientDataJSON(typ, challenge, origin string) []byte {
	bs, _ := json.Marshal(clientData{Type: typ, Challenge: challenge, Origin: origin})
	return bs
}

// register answers a "begin" response that asked for enrolment.
func (k *softKey) register(challenge, rpID, origin string) serveCheckFinishRequest {
	pub, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	if err != nil {
		k.t.Fatal(err)
	}
	return serveCheckFinishRequest{
		Challenge:         challenge,
		CredentialID:      b64.EncodeToString(k.id),
		ClientDataJSON:    b64.EncodeToString(clientDataJSON("webauthn.create", challenge, origin)),
		AuthenticatorData: b64.EncodeToString(k.authData(rpID)),
		PublicKey:         b64.EncodeToString(pub),
	}
}

// assert answers a "begin" response that asked for an assertion.
func (k *softKey) assert(challenge, rpID, origin string) serveCheckFinishRequest {
	cdj := clientDataJSON("webauthn.get", challenge, origin)
	ad := k.authData(rpID)
	cdh := sha256.Sum256(cdj)
	d := sha256.Sum256(append(append([]byte(nil), ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return serveCheckFinishRequest{
		Challenge:         challenge,
		CredentialID:      b64.EncodeToString(k.id),
		ClientDataJSON:    b64.EncodeToString(cdj),
		AuthenticatorData: b64.EncodeToString(ad),
		Signature:         b64.EncodeToString(sig),
	}
}

const (
	checkHost   = "example.ts.net"
	checkOrigin = "https://example.ts.net"
	laptopIP    = "100.150.151.152"
	phoneIP     = "100.150.151.154"
	taggedIP    = "100.150.151.153"
)

func newServeCheckBackend(t *testing.T) (*LocalBackend, *tstest.Clock) {
	b := newTestBackend(t)
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(1_700_000_000, 0)})
	b.clock = clock

	// Add a second device for the same user, to check timers are per device.
	nm := b.currentNode().NetMap()
	peers := append([]tailcfg.NodeView(nil), nm.Peers...)
	peers = append(peers, (&tailcfg.Node{
		ID:           154,
		StableID:     "phone",
		ComputedName: "phone",
		User:         tailcfg.UserID(1),
		Key:          makeNodeKeyFromID(154),
		Addresses:    []netip.Prefix{netip.MustParsePrefix(phoneIP + "/32")},
	}).View())
	for i, p := range peers {
		if p.ID() == 152 {
			n := p.AsStruct()
			n.StableID = "laptop"
			peers[i] = n.View()
		}
	}
	b.currentNode().SetNetMap(&netmap.NetworkMap{
		SelfNode:     nm.SelfNode,
		UserProfiles: nm.UserProfiles,
		Peers:        peers,
	})

	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			checkHost + ":443": {Handlers: map[string]*ipn.HTTPHandler{
				"/":      {Text: "app a", Check: true, CheckPeriod: tstime.GoDuration{Duration: 5 * time.Minute}},
				"/b/":    {Text: "app b", Check: true},
				"/open/": {Text: "open"},
			}},
		},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}
	return b, clock
}

func serveCheckDo(t *testing.T, b *LocalBackend, srcIP, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "https://"+checkHost+target, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{ServerName: checkHost}
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{
		DestPort: 443,
		SrcAddr:  netip.MustParseAddrPort(srcIP + ":1234"),
	}))
	w := httptest.NewRecorder()
	b.serveWebHandler(w, req)
	return w
}

type beginResp struct {
	Register  bool
	Challenge string
	RPID      string `json:"rpId"`
	Allow     []string
}

func serveCheckBegin(t *testing.T, b *LocalBackend, srcIP, mount string) beginResp {
	t.Helper()
	w := serveCheckDo(t, b, srcIP, "POST", serveCheckPathPrefix+"begin?m="+url.QueryEscape(mount), nil)
	if w.Code != 200 {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	var br beginResp
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatal(err)
	}
	return br
}

func serveCheckFinish(t *testing.T, b *LocalBackend, srcIP, mount string, req serveCheckFinishRequest) int {
	t.Helper()
	bs, _ := json.Marshal(req)
	return serveCheckDo(t, b, srcIP, "POST", serveCheckPathPrefix+"finish?m="+url.QueryEscape(mount), bs).Code
}

func wantRedirectToCheck(t *testing.T, w *httptest.ResponseRecorder, mount string) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("got %d %q, want redirect to check", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Path != serveCheckPathPrefix || loc.Query().Get("m") != mount {
		t.Fatalf("Location = %q, want check page for %q", w.Header().Get("Location"), mount)
	}
}

func wantBody(t *testing.T, w *httptest.ResponseRecorder, body string) {
	t.Helper()
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("got %d %q, want 200 %q", w.Code, w.Body, body)
	}
}

func TestServeCheck(t *testing.T) {
	b, clock := newServeCheckBackend(t)
	key := newSoftKey(t)

	// Unchecked handlers are untouched.
	wantBody(t, serveCheckDo(t, b, laptopIP, "GET", "/open/", nil), "open")

	// First use: redirected to the step-up page, which tailscaled serves.
	wantRedirectToCheck(t, serveCheckDo(t, b, laptopIP, "GET", "/", nil), "/")
	page := serveCheckDo(t, b, laptopIP, "GET", serveCheckPathPrefix+"?m=%2F&next=%2F", nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "some-peer") {
		t.Fatalf("check page: %d %q", page.Code, page.Body)
	}

	// Non-browser requests get a 403, not a redirect.
	if w := serveCheckDo(t, b, laptopIP, "POST", "/", nil); w.Code != http.StatusForbidden {
		t.Fatalf("POST before check: got %d, want 403", w.Code)
	}

	// Tagged devices have no user to check.
	if w := serveCheckDo(t, b, taggedIP, "GET", "/", nil); w.Code != http.StatusForbidden {
		t.Fatalf("tagged peer: got %d, want 403", w.Code)
	}

	// Enrol a key; enrolment counts as the first check.
	br := serveCheckBegin(t, b, laptopIP, "/")
	if !br.Register || br.RPID != checkHost {
		t.Fatalf("begin = %+v, want registration for %q", br, checkHost)
	}
	if code := serveCheckFinish(t, b, laptopIP, "/", key.register(br.Challenge, br.RPID, checkOrigin)); code != 200 {
		t.Fatalf("register: got %d", code)
	}
	wantBody(t, serveCheckDo(t, b, laptopIP, "GET", "/", nil), "app a")

	// Each handler has its own timer.
	wantRedirectToCheck(t, serveCheckDo(t, b, laptopIP, "GET", "/b/", nil), "/b/")
	// Each device has its own timer.
	wantRedirectToCheck(t, serveCheckDo(t, b, phoneIP, "GET", "/", nil), "/")

	// The phone asserts with the same user's key, for its own pair only.
	br = serveCheckBegin(t, b, phoneIP, "/")
	if br.Register || len(br.Allow) != 1 {
		t.Fatalf("begin = %+v, want assertion with one credential", br)
	}
	if code := serveCheckFinish(t, b, phoneIP, "/", key.assert(br.Challenge, br.RPID, checkOrigin)); code != 200 {
		t.Fatalf("assert: got %d", code)
	}
	wantBody(t, serveCheckDo(t, b, phoneIP, "GET", "/", nil), "app a")
	wantRedirectToCheck(t, serveCheckDo(t, b, phoneIP, "GET", "/b/", nil), "/b/")

	// The check lapses after the handler's period.
	clock.Advance(4 * time.Minute)
	wantBody(t, serveCheckDo(t, b, laptopIP, "GET", "/", nil), "app a")
	clock.Advance(2 * time.Minute)
	wantRedirectToCheck(t, serveCheckDo(t, b, laptopIP, "GET", "/", nil), "/")
}

func TestServeCheckRejects(t *testing.T) {
	b, _ := newServeCheckBackend(t)
	key := newSoftKey(t)
	br := serveCheckBegin(t, b, laptopIP, "/")
	if code := serveCheckFinish(t, b, laptopIP, "/", key.register(br.Challenge, br.RPID, checkOrigin)); code != 200 {
		t.Fatalf("register: got %d", code)
	}

	other := newSoftKey(t) // same credential ID, different private key
	tests := []struct {
		name  string
		mount string // mount the challenge was issued for
		src   string // device finishing the check
		req   func(challenge string) serveCheckFinishRequest
	}{
		{"wrong-key", "/b/", laptopIP, func(c string) serveCheckFinishRequest { return other.assert(c, checkHost, checkOrigin) }},
		{"wrong-origin", "/b/", laptopIP, func(c string) serveCheckFinishRequest {
			return key.assert(c, checkHost, "https://evil.example.com")
		}},
		{"wrong-rp", "/b/", laptopIP, func(c string) serveCheckFinishRequest { return key.assert(c, "evil.example.com", checkOrigin) }},
		{"wrong-challenge", "/b/", laptopIP, func(c string) serveCheckFinishRequest {
			r := key.assert("bm9wZQ", checkHost, checkOrigin)
			r.Challenge = c
			return r
		}},
		{"other-device", "/b/", phoneIP, func(c string) serveCheckFinishRequest { return key.assert(c, checkHost, checkOrigin) }},
		{"second-enrolment", "/b/", laptopIP, func(c string) serveCheckFinishRequest { return other.register(c, checkHost, checkOrigin) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := serveCheckBegin(t, b, laptopIP, tt.mount)
			if code := serveCheckFinish(t, b, tt.src, tt.mount, tt.req(br.Challenge)); code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", code)
			}
			wantRedirectToCheck(t, serveCheckDo(t, b, tt.src, "GET", tt.mount, nil), tt.mount)
		})
	}

	// A challenge is single use.
	br = serveCheckBegin(t, b, laptopIP, "/b/")
	req := key.assert(br.Challenge, checkHost, checkOrigin)
	if code := serveCheckFinish(t, b, laptopIP, "/b/", req); code != 200 {
		t.Fatalf("assert: got %d", code)
	}
	if code := serveCheckFinish(t, b, laptopIP, "/b/", req); code != http.StatusForbidden {
		t.Fatalf("replay: got %d, want 403", code)
	}

	// A sign count that doesn't go up means a cloned key.
	br = serveCheckBegin(t, b, laptopIP, "/")
	key.count -= 2
	if code := serveCheckFinish(t, b, laptopIP, "/", key.assert(br.Challenge, checkHost, checkOrigin)); code != http.StatusForbidden {
		t.Fatalf("stale sign count: got %d, want 403", code)
	}

	// The step-up endpoints are only for checked handlers; otherwise the
	// path reaches the app as usual.
	wantBody(t, serveCheckDo(t, b, laptopIP, "POST", serveCheckPathPrefix+"begin?m=%2Fopen%2F", nil), "app a")
}
