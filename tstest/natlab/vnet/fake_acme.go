// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

// This file implements a minimal fake ACME (RFC 8555) certificate authority
// used by TestACMECertServeHTTPS in tstest/natlab/vmtest. It exists so that
// natlab VM tests can exercise `tailscale cert` and `tailscale serve` end to
// end without reaching out to Let's Encrypt.
//
// Only the parts of ACME exercised by that test are implemented: the dns-01
// challenge flow, a single hard-coded account, no JWS signature verification,
// no key rollover, no nonce tracking, no rate limiting. The TLS root is
// freshly generated per server.
//
// If a future test needs more of the protocol, prefer switching to
// https://github.com/letsencrypt/pebble (the official Let's Encrypt test
// ACME server) rather than fleshing this file out further. The threshold for
// "more complicated" should be low.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"tailscale.com/util/httpm"
)

// fakeACMEServer is an in-process fake ACME (RFC 8555) CA used by natlab
// VM tests. See the file-level comment for scope and limitations.
//
// The zero value is not usable; construct via [newFakeACMEServer].
type fakeACMEServer struct {
	// baseURL is the externally visible URL prefix at which the server is
	// reachable (no trailing slash). All issued URLs are formed by appending
	// to baseURL.
	baseURL string

	mu      sync.Mutex
	rootKey *ecdsa.PrivateKey // CA signing key
	rootDER []byte            // CA cert, DER-encoded
	nextID  int64             // monotonically increasing ID source for orders/authzs/challenges/certs
	// lookupTXT, if non-nil, returns the TXT records visible to the CA for
	// dns-01 challenge validation. It is set by the surrounding [Server]
	// after construction.
	lookupTXT func(string) []string
	orders    map[string]*fakeACMEOrder // order ID → order
	authzs    map[string]*fakeACMEAuthz // authz ID → authz
	certsPEM  map[string][]byte         // cert ID → issued cert chain PEM
}

// fakeACMEOrder is the in-memory state for one ACME order.
//
// Status is one of "pending", "ready", or "valid", matching RFC 8555 §7.1.6.
// The terminal "invalid" state is not modeled.
type fakeACMEOrder struct {
	id          string
	status      string
	identifiers []fakeACMEIdentifier
	authzURLs   []string
	finalizeURL string
	certURL     string // empty until status == "valid"
}

// fakeACMEAuthz is the in-memory state for one ACME authorization. Each
// authorization carries a single dns-01 challenge; other challenge types
// are not modeled.
type fakeACMEAuthz struct {
	id         string
	status     string // "pending" or "valid"
	identifier fakeACMEIdentifier
	challenge  fakeACMEChallenge
}

// fakeACMEIdentifier identifies a domain to be authorized.
// It is serialized as the ACME "identifier" JSON object.
type fakeACMEIdentifier struct {
	Type  string `json:"type"`  // always "dns" in practice
	Value string `json:"value"` // domain name, possibly with a "*." wildcard prefix
}

// fakeACMEChallenge is the JSON shape of a single ACME challenge,
// per RFC 8555 §8.
type fakeACMEChallenge struct {
	URL    string `json:"url"`
	Type   string `json:"type"`  // always "dns-01"
	Token  string `json:"token"` // not used to derive a real key authorization; just echoed back
	Status string `json:"status"`
}

// newFakeACMEServer returns a new fake ACME server that will advertise
// itself at baseURL. A fresh ECDSA P-256 CA key and a self-signed root
// certificate are generated. The caller is responsible for actually serving
// HTTP at baseURL and routing requests to [fakeACMEServer.ServeHTTP].
func newFakeACMEServer(baseURL string) *fakeACMEServer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		panic(fmt.Sprintf("vnet: generating fake ACME root key: %v", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "natlab fake ACME root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("vnet: creating fake ACME root: %v", err))
	}
	return &fakeACMEServer{
		baseURL:  strings.TrimRight(baseURL, "/"),
		rootKey:  key,
		rootDER:  der,
		nextID:   1,
		orders:   map[string]*fakeACMEOrder{},
		authzs:   map[string]*fakeACMEAuthz{},
		certsPEM: map[string][]byte{},
	}
}

// directoryURL returns the ACME directory URL for s, suitable for setting
// TS_DEBUG_ACME_DIRECTORY_URL in a tailscaled under test.
func (s *fakeACMEServer) directoryURL() string {
	return s.baseURL + "/directory"
}

// rootPEM returns the PEM-encoded root certificate that signs all certs
// issued by s. Clients that want to verify those certs must trust it.
func (s *fakeACMEServer) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.rootDER})
}

// ServeHTTP routes ACME protocol requests to the appropriate handler.
// It is intended to be installed as the [http.Handler] for s.baseURL.
func (s *fakeACMEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	switch {
	case r.Method == httpm.GET && r.URL.Path == "/directory":
		writeACMEJSON(w, http.StatusOK, struct {
			NewNonce   string `json:"newNonce"`
			NewAccount string `json:"newAccount"`
			NewOrder   string `json:"newOrder"`
			RevokeCert string `json:"revokeCert"`
		}{
			NewNonce:   s.baseURL + "/new-nonce",
			NewAccount: s.baseURL + "/new-account",
			NewOrder:   s.baseURL + "/new-order",
			RevokeCert: s.baseURL + "/revoke-cert",
		})
	case (r.Method == httpm.HEAD || r.Method == httpm.GET) && r.URL.Path == "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case r.Method == httpm.POST && r.URL.Path == "/new-account":
		s.serveNewAccount(w, r)
	case r.Method == httpm.POST && r.URL.Path == "/new-order":
		s.serveNewOrder(w, r)
	case r.Method == httpm.POST && strings.HasPrefix(r.URL.Path, "/authz/"):
		s.serveAuthz(w, r)
	case r.Method == httpm.POST && strings.HasPrefix(r.URL.Path, "/challenge/"):
		s.serveChallenge(w, r)
	case r.Method == httpm.POST && strings.HasPrefix(r.URL.Path, "/order/") && strings.HasSuffix(r.URL.Path, "/finalize"):
		s.serveFinalize(w, r)
	case r.Method == httpm.POST && strings.HasPrefix(r.URL.Path, "/order/"):
		s.serveOrder(w, r)
	case r.Method == httpm.POST && strings.HasPrefix(r.URL.Path, "/cert/"):
		s.serveCert(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveNewAccount handles the ACME newAccount endpoint.
//
// The fake only supports a single account: every newAccount request returns
// the same /account/1 URL, and no per-account state is tracked. Tests that
// need multiple distinct accounts will need to extend this.
func (s *fakeACMEServer) serveNewAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		io.Copy(io.Discard, r.Body)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.OnlyReturnExisting {
		writeACMEProblemType(w, http.StatusBadRequest, "accountDoesNotExist", "account does not exist")
		return
	}
	w.Header().Set("Location", s.baseURL+"/account/1")
	writeACMEJSON(w, http.StatusCreated, struct {
		Status string `json:"status"`
	}{Status: "valid"})
}

// serveNewOrder handles the ACME newOrder endpoint. It allocates an order
// and one authorization (with a single dns-01 challenge) per identifier in
// the request, all in "pending" status.
func (s *fakeACMEServer) serveNewOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifiers []fakeACMEIdentifier `json:"identifiers"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	orderID := s.allocIDLocked()
	orderURL := s.baseURL + "/order/" + orderID
	o := &fakeACMEOrder{
		id:          orderID,
		status:      "pending",
		identifiers: req.Identifiers,
		finalizeURL: orderURL + "/finalize",
	}
	for _, ident := range req.Identifiers {
		authzID := s.allocIDLocked()
		chalID := s.allocIDLocked()
		chal := fakeACMEChallenge{
			URL:    s.baseURL + "/challenge/" + chalID,
			Type:   "dns-01",
			Token:  "token-" + chalID,
			Status: "pending",
		}
		az := &fakeACMEAuthz{
			id:         authzID,
			status:     "pending",
			identifier: ident,
			challenge:  chal,
		}
		authzURL := s.baseURL + "/authz/" + authzID
		s.authzs[authzID] = az
		o.authzURLs = append(o.authzURLs, authzURL)
	}
	s.orders[orderID] = o
	w.Header().Set("Location", orderURL)
	writeACMEJSON(w, http.StatusCreated, s.orderResponseLocked(o))
}

// serveAuthz handles GET-via-POST of an authorization object.
func (s *fakeACMEServer) serveAuthz(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	s.mu.Lock()
	defer s.mu.Unlock()
	az := s.authzs[id]
	if az == nil {
		http.NotFound(w, r)
		return
	}
	writeACMEJSON(w, http.StatusOK, s.authzResponseLocked(az))
}

// serveChallenge handles the client's "I'm ready, please validate" POST to
// a challenge URL. It looks up the expected TXT record via s.lookupTXT and,
// if any record is present, marks both the challenge and its enclosing
// authorization as valid (and re-evaluates any pending orders).
//
// The TXT record contents are not validated against the JWK thumbprint; any
// non-empty record satisfies the challenge. That is intentional for these
// tests but is not how a real ACME server behaves.
func (s *fakeACMEServer) serveChallenge(w http.ResponseWriter, r *http.Request) {
	// Keep issuance pending long enough for `tailscale cert` to print the
	// cert-pending health warning it is watching for.
	time.Sleep(3 * time.Second)

	id := strings.TrimPrefix(r.URL.Path, "/challenge/")
	s.mu.Lock()
	defer s.mu.Unlock()
	var az *fakeACMEAuthz
	for _, a := range s.authzs {
		if strings.TrimPrefix(a.challenge.URL, s.baseURL+"/challenge/") == id {
			az = a
			break
		}
	}
	if az == nil {
		http.NotFound(w, r)
		return
	}
	name := "_acme-challenge." + strings.TrimPrefix(az.identifier.Value, "*.")
	if s.lookupTXT == nil || len(s.lookupTXT(name)) == 0 {
		writeACMEProblem(w, http.StatusForbidden, "dns TXT record not found")
		return
	}
	az.status = "valid"
	az.challenge.Status = "valid"
	s.updateOrdersLocked()
	writeACMEJSON(w, http.StatusOK, az.challenge)
}

// serveOrder handles GET-via-POST of an order object.
func (s *fakeACMEServer) serveOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	id = strings.TrimSuffix(id, "/finalize")
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Location", s.baseURL+"/order/"+id)
	writeACMEJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

// serveFinalize handles a POST to /order/<id>/finalize. It parses the
// supplied CSR, issues a leaf certificate signed by the fake root, and
// transitions the order to "valid".
func (s *fakeACMEServer) serveFinalize(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/order/"), "/finalize")
	var req struct {
		CSR string `json:"csr"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o == nil {
		http.NotFound(w, r)
		return
	}
	if o.status != "ready" && o.status != "valid" {
		writeACMEProblem(w, http.StatusForbidden, "order is not ready")
		return
	}
	certPEM, err := s.issueCertLocked(csr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	certID := s.allocIDLocked()
	o.status = "valid"
	o.certURL = s.baseURL + "/cert/" + certID
	s.certsPEM[certID] = certPEM
	w.Header().Set("Location", s.baseURL+"/order/"+id)
	writeACMEJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

// serveCert returns the PEM-encoded issued certificate chain (leaf + root)
// for a previously finalized order.
func (s *fakeACMEServer) serveCert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	s.mu.Lock()
	cert := append([]byte(nil), s.certsPEM[id]...)
	s.mu.Unlock()
	if len(cert) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(cert)
}

// allocIDLocked returns a fresh decimal ID. s.mu must be held.
func (s *fakeACMEServer) allocIDLocked() string {
	id := s.nextID
	s.nextID++
	return fmt.Sprint(id)
}

// updateOrdersLocked promotes any pending order whose authorizations are
// all valid to the "ready" state. s.mu must be held.
func (s *fakeACMEServer) updateOrdersLocked() {
	for _, o := range s.orders {
		if o.status != "pending" {
			continue
		}
		ready := true
		for _, u := range o.authzURLs {
			id := strings.TrimPrefix(u, s.baseURL+"/authz/")
			if s.authzs[id].status != "valid" {
				ready = false
			}
		}
		if ready {
			o.status = "ready"
		}
	}
}

// orderResponseLocked returns the JSON-shaped view of o that ACME clients
// expect. s.mu must be held.
func (s *fakeACMEServer) orderResponseLocked(o *fakeACMEOrder) any {
	return struct {
		Status         string               `json:"status"`
		Identifiers    []fakeACMEIdentifier `json:"identifiers"`
		Authorizations []string             `json:"authorizations"`
		Finalize       string               `json:"finalize"`
		Certificate    string               `json:"certificate"`
	}{
		Status:         o.status,
		Identifiers:    o.identifiers,
		Authorizations: o.authzURLs,
		Finalize:       o.finalizeURL,
		Certificate:    o.certURL,
	}
}

// authzResponseLocked returns the JSON-shaped view of az that ACME clients
// expect. s.mu must be held.
func (s *fakeACMEServer) authzResponseLocked(az *fakeACMEAuthz) any {
	return struct {
		Status     string              `json:"status"`
		Identifier fakeACMEIdentifier  `json:"identifier"`
		Challenges []fakeACMEChallenge `json:"challenges"`
	}{
		Status:     az.status,
		Identifier: az.identifier,
		Challenges: []fakeACMEChallenge{az.challenge},
	}
}

// issueCertLocked signs a 24-hour leaf cert for csr using s's root and
// returns the leaf-then-root PEM chain. s.mu must be held.
func (s *fakeACMEServer) issueCertLocked(csr *x509.CertificateRequest) ([]byte, error) {
	serial := big.NewInt(time.Now().UnixNano())
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}
	root, err := x509.ParseCertificate(s.rootDER)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, root, csr.PublicKey, s.rootKey)
	if err != nil {
		return nil, err
	}
	var b []byte
	b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b = append(b, s.rootPEM()...)
	return b, nil
}

// decodeJWSPayload extracts the inner JSON payload from an ACME JWS-wrapped
// request body and unmarshals it into v. The JWS signature, protected
// header, and key are not inspected: this is a fake server, and we trust
// whatever the client sends.
//
// ACME (RFC 8555) JWS payloads use unpadded base64url encoding, so we
// decode Payload as a string with [base64.RawURLEncoding] rather than as a
// []byte field (which encoding/json would decode with [base64.StdEncoding]).
func decodeJWSPayload(r *http.Request, v any) error {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return err
	}
	if jws.Payload == "" {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

// writeACMEJSON serializes v as JSON and writes it as an ACME response with
// the given status code.
func writeACMEJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeACMEProblem writes an ACME "rejectedIdentifier" problem document.
// This is the catch-all error used when no more specific ACME error type
// fits.
func writeACMEProblem(w http.ResponseWriter, code int, detail string) {
	writeACMEProblemType(w, code, "rejectedIdentifier", detail)
}

// writeACMEProblemType writes an ACME problem document with the given
// problem type (the trailing component of urn:ietf:params:acme:error:*)
// and detail message.
func writeACMEProblemType(w http.ResponseWriter, code int, problemType, detail string) {
	writeACMEJSON(w, code, struct {
		Status int    `json:"status"`
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}{
		Status: code,
		Type:   "urn:ietf:params:acme:error:" + problemType,
		Detail: detail,
	})
}
