// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package acmetest implements a minimal fake ACME (RFC 8555) certificate
// authority for tests of tailscaled's certificate issuance. It lets a test
// exercise `tailscale cert` and `tailscale serve` without reaching out to
// Let's Encrypt.
//
// Only the parts of ACME the Tailscale client uses are implemented: one
// order per request with one challenge per identifier, dns-01 and
// tls-alpn-01, a single hard-coded account, no JWS signature verification,
// no key rollover, no nonce tracking, no rate limiting. The TLS root is
// freshly generated per server.
//
// If a future test needs more of the protocol, prefer switching to
// https://github.com/letsencrypt/pebble (the official Let's Encrypt test
// ACME server) rather than fleshing this out further. The threshold for
// "more complicated" should be low.
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/util/httpm"
)

// Server is an in-process fake ACME CA. Construct it with [New] or
// [Start]; the zero value is not usable.
//
// The exported fields configure how challenges are validated. Set them
// before the first request.
type Server struct {
	// ChallengeType is the challenge offered on every authorization:
	// "dns-01" (the default) or "tls-alpn-01".
	ChallengeType string

	// LookupTXT returns the TXT records visible to the CA for a name. It
	// is how dns-01 challenges are validated when Validate is nil: any
	// record at _acme-challenge.<identifier> satisfies the challenge.
	// The record contents are not checked against the key authorization.
	LookupTXT func(name string) []string

	// Validate, if non-nil, decides the outcome of a challenge in place
	// of the default. A nil return marks the authorization valid. A
	// non-nil return marks the challenge, its authorization, and its
	// order invalid, with the error text as the problem detail, which
	// is what a CA does when it cannot see the expected record.
	Validate func(identifier, challengeType string) error

	// ValidationDelay is how long the server holds the client's request
	// to validate a challenge before answering. It keeps an order pending
	// long enough for a test to observe in-progress state.
	ValidationDelay time.Duration

	baseURL string // externally visible URL prefix, no trailing slash

	mu       sync.Mutex
	rootKey  *ecdsa.PrivateKey
	rootDER  []byte
	nextID   int64
	orders   map[string]*order
	authzs   map[string]*authz
	certsPEM map[string][]byte
	requests map[string]int // POST-as-GET and POST counts by path
}

// order is the in-memory state for one ACME order. Status is one of
// "pending", "ready", "valid", or "invalid", per RFC 8555 §7.1.6.
type order struct {
	id          string
	status      string
	identifiers []identifier
	authzURLs   []string
	finalizeURL string
	certURL     string // empty until status == "valid"
}

// authz is the in-memory state for one ACME authorization. Each carries
// a single challenge.
type authz struct {
	id         string
	status     string // "pending", "valid", or "invalid"
	identifier identifier
	challenge  challenge
}

// identifier is the ACME "identifier" JSON object.
type identifier struct {
	Type  string `json:"type"`  // always "dns" in practice
	Value string `json:"value"` // domain name, possibly with a "*." wildcard prefix
}

// challenge is the JSON shape of a single ACME challenge, per RFC 8555 §8.
type challenge struct {
	URL    string   `json:"url"`
	Type   string   `json:"type"`
	Token  string   `json:"token"` // not used to derive a real key authorization; just echoed back
	Status string   `json:"status"`
	Error  *problem `json:"error,omitzero"`
}

// problem is an ACME problem document (RFC 7807).
type problem struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// New returns a Server that will advertise itself at baseURL. The caller
// is responsible for serving HTTP at baseURL and routing requests to
// [Server.ServeHTTP]. A fresh ECDSA P-256 root key and self-signed root
// certificate are generated.
func New(baseURL string) *Server {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		panic(fmt.Sprintf("acmetest: generating root key: %v", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmetest fake ACME root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("acmetest: creating root certificate: %v", err))
	}
	return &Server{
		ChallengeType: "dns-01",
		baseURL:       strings.TrimRight(baseURL, "/"),
		rootKey:       key,
		rootDER:       der,
		nextID:        1,
		orders:        map[string]*order{},
		authzs:        map[string]*authz{},
		certsPEM:      map[string][]byte{},
		requests:      map[string]int{},
	}
}

// Start returns a Server listening on a loopback [httptest.Server] that
// is closed when the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	var s *Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	s = New(ts.URL)
	return s
}

// DirectoryURL returns the ACME directory URL, suitable for setting
// TS_DEBUG_ACME_DIRECTORY_URL in a tailscaled under test or as the
// DirectoryURL of an ACME client.
func (s *Server) DirectoryURL() string {
	return s.baseURL + "/directory"
}

// RootPEM returns the PEM-encoded root certificate that signs every
// certificate the server issues.
func (s *Server) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.rootDER})
}

// Root returns the parsed root certificate.
func (s *Server) Root() *x509.Certificate {
	root, err := x509.ParseCertificate(s.rootDER)
	if err != nil {
		panic(err)
	}
	return root
}

// Requests reports how many requests the server has received for path,
// not counting the directory and nonce endpoints. Order paths are
// "/order/<n>", authorization paths "/authz/<n>", and IDs are allocated
// from 1 in the order the objects are created: the first order is 1, its
// first authorization 2, and that authorization's challenge 3.
func (s *Server) Requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[path]
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	if r.Method == httpm.POST {
		s.mu.Lock()
		s.requests[r.URL.Path]++
		s.mu.Unlock()
	}
	switch {
	case r.Method == httpm.GET && r.URL.Path == "/directory":
		writeJSON(w, http.StatusOK, struct {
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
// The fake only supports a single account: every newAccount request
// returns the same /account/1 URL, and no per-account state is tracked.
func (s *Server) serveNewAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		io.Copy(io.Discard, r.Body)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", s.baseURL+"/account/1")
	code := http.StatusCreated
	if req.OnlyReturnExisting {
		code = http.StatusOK
	}
	writeJSON(w, code, struct {
		Status string `json:"status"`
	}{Status: "valid"})
}

// serveNewOrder handles the ACME newOrder endpoint. It allocates an order
// and one authorization, with a single challenge of s.ChallengeType, per
// identifier in the request, all in "pending" status.
func (s *Server) serveNewOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifiers []identifier `json:"identifiers"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	orderID := s.allocIDLocked()
	orderURL := s.baseURL + "/order/" + orderID
	o := &order{
		id:          orderID,
		status:      "pending",
		identifiers: req.Identifiers,
		finalizeURL: orderURL + "/finalize",
	}
	for _, ident := range req.Identifiers {
		authzID := s.allocIDLocked()
		chalID := s.allocIDLocked()
		az := &authz{
			id:         authzID,
			status:     "pending",
			identifier: ident,
			challenge: challenge{
				URL:    s.baseURL + "/challenge/" + chalID,
				Type:   s.ChallengeType,
				Token:  "token-" + chalID,
				Status: "pending",
			},
		}
		s.authzs[authzID] = az
		o.authzURLs = append(o.authzURLs, s.baseURL+"/authz/"+authzID)
	}
	s.orders[orderID] = o
	w.Header().Set("Location", orderURL)
	writeJSON(w, http.StatusCreated, s.orderResponseLocked(o))
}

// serveAuthz handles POST-as-GET of an authorization object.
func (s *Server) serveAuthz(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	s.mu.Lock()
	defer s.mu.Unlock()
	az := s.authzs[id]
	if az == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.authzResponseLocked(az))
}

// serveChallenge handles the client's "I'm ready, please validate" POST to
// a challenge URL. It validates per s.Validate, or by default looks up the
// dns-01 TXT record via s.LookupTXT, then marks the challenge and its
// authorization valid or invalid and re-evaluates the orders. As with a
// real CA, the response is the challenge object; the outcome is on the
// authorization.
func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request) {
	time.Sleep(s.ValidationDelay)

	id := strings.TrimPrefix(r.URL.Path, "/challenge/")
	s.mu.Lock()
	defer s.mu.Unlock()
	var az *authz
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
	if err := s.validateLocked(az); err != nil {
		az.status = "invalid"
		az.challenge.Status = "invalid"
		az.challenge.Error = &problem{
			Status: http.StatusForbidden,
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: err.Error(),
		}
	} else {
		az.status = "valid"
		az.challenge.Status = "valid"
	}
	s.updateOrdersLocked()
	writeJSON(w, http.StatusOK, az.challenge)
}

// validateLocked decides the outcome of az's challenge. s.mu must be held.
func (s *Server) validateLocked(az *authz) error {
	if s.Validate != nil {
		return s.Validate(az.identifier.Value, az.challenge.Type)
	}
	switch az.challenge.Type {
	case "dns-01":
		name := "_acme-challenge." + strings.TrimPrefix(az.identifier.Value, "*.")
		if s.LookupTXT == nil || len(s.LookupTXT(name)) == 0 {
			return errors.New("No TXT record found at " + name)
		}
		return nil
	default:
		// There is nothing to look up for tls-alpn-01 in-process.
		return nil
	}
}

// serveOrder handles POST-as-GET of an order object.
func (s *Server) serveOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Location", s.baseURL+"/order/"+id)
	writeJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

// serveFinalize handles a POST to /order/<id>/finalize. It parses the
// supplied CSR, issues a leaf certificate signed by the root, and
// transitions the order to "valid".
func (s *Server) serveFinalize(w http.ResponseWriter, r *http.Request) {
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
		writeProblem(w, http.StatusForbidden, "orderNotReady", "order is not ready")
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
	writeJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

// serveCert returns the PEM-encoded issued certificate chain (leaf then
// root) for a previously finalized order.
func (s *Server) serveCert(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) allocIDLocked() string {
	id := s.nextID
	s.nextID++
	return fmt.Sprint(id)
}

// updateOrdersLocked moves a pending order to "ready" once all its
// authorizations are valid, and to "invalid" once any is. s.mu must be
// held.
func (s *Server) updateOrdersLocked() {
	for _, o := range s.orders {
		if o.status != "pending" {
			continue
		}
		ready := true
		for _, u := range o.authzURLs {
			switch s.authzs[strings.TrimPrefix(u, s.baseURL+"/authz/")].status {
			case "invalid":
				o.status = "invalid"
			case "valid":
			default:
				ready = false
			}
		}
		if ready && o.status == "pending" {
			o.status = "ready"
		}
	}
}

// orderResponseLocked returns the JSON view of o. s.mu must be held.
func (s *Server) orderResponseLocked(o *order) any {
	return struct {
		Status         string       `json:"status"`
		Identifiers    []identifier `json:"identifiers"`
		Authorizations []string     `json:"authorizations"`
		Finalize       string       `json:"finalize"`
		Certificate    string       `json:"certificate,omitempty"`
	}{
		Status:         o.status,
		Identifiers:    o.identifiers,
		Authorizations: o.authzURLs,
		Finalize:       o.finalizeURL,
		Certificate:    o.certURL,
	}
}

// authzResponseLocked returns the JSON view of az. s.mu must be held.
func (s *Server) authzResponseLocked(az *authz) any {
	return struct {
		Status     string      `json:"status"`
		Identifier identifier  `json:"identifier"`
		Challenges []challenge `json:"challenges"`
	}{
		Status:     az.status,
		Identifier: az.identifier,
		Challenges: []challenge{az.challenge},
	}
}

// issueCertLocked signs a 24-hour leaf cert for csr using the root and
// returns the leaf-then-root PEM chain. s.mu must be held.
func (s *Server) issueCertLocked(csr *x509.CertificateRequest) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, s.Root(), csr.PublicKey, s.rootKey)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), s.RootPEM()...), nil
}

// decodeJWSPayload extracts the inner JSON payload from an ACME JWS-wrapped
// request body and unmarshals it into v. The JWS signature, protected
// header, and key are not inspected: this is a fake server, and we trust
// whatever the client sends.
//
// ACME (RFC 8555) JWS payloads use unpadded base64url encoding, so Payload
// is decoded as a string with [base64.RawURLEncoding] rather than as a
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

// writeJSON serializes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeProblem writes an ACME problem document with the given problem type
// (the trailing component of urn:ietf:params:acme:error:*) and detail.
func writeProblem(w http.ResponseWriter, code int, problemType, detail string) {
	writeJSON(w, code, problem{
		Status: code,
		Type:   "urn:ietf:params:acme:error:" + problemType,
		Detail: detail,
	})
}
