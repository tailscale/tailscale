// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIPACME is a minimal fake ACME (RFC 8555) certificate authority
// for testing ipCertManager. It implements just enough of the protocol
// for http-01 order flows with IP address identifiers and the
// "shortlived" profile: one order at a time, no JWS signature
// verification, no nonce tracking.
type fakeIPACME struct {
	t             *testing.T
	srv           *httptest.Server
	challengeBase string // base URL at which http-01 challenges are fetched

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu          sync.Mutex
	orders      int    // number of orders created
	gotProfile  string // profile of the last order
	gotIDType   string // identifier type of the last order
	gotIDValue  string // identifier value of the last order
	authzStatus string // "pending" or "valid"
	orderStatus string // "pending", "ready", or "valid"
	token       string
	certPEM     []byte
}

func newFakeIPACME(t *testing.T) *fakeIPACME {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake IP ACME root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIPACME{
		t:      t,
		caKey:  caKey,
		caCert: caCert,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIPACME) directoryURL() string { return f.srv.URL + "/directory" }

func (f *fakeIPACME) numOrders() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orders
}

func (f *fakeIPACME) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "test-nonce")
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	orderJSON := func() any {
		return map[string]any{
			"status":         f.orderStatus,
			"identifiers":    []map[string]string{{"type": f.gotIDType, "value": f.gotIDValue}},
			"authorizations": []string{f.srv.URL + "/authz/1"},
			"finalize":       f.srv.URL + "/finalize/1",
			"certificate":    f.srv.URL + "/cert/1",
		}
	}
	switch {
	case r.URL.Path == "/directory":
		writeJSON(map[string]any{
			"newNonce":   f.srv.URL + "/new-nonce",
			"newAccount": f.srv.URL + "/new-account",
			"newOrder":   f.srv.URL + "/new-order",
			"revokeCert": f.srv.URL + "/revoke-cert",
			"keyChange":  f.srv.URL + "/key-change",
			"meta": map[string]any{
				"profiles": map[string]string{
					"classic":         "the default profile",
					shortlivedProfile: "six day certificates",
				},
			},
		})
	case r.URL.Path == "/new-nonce":
		// The Replay-Nonce header was already set above.
	case r.URL.Path == "/new-account":
		w.Header().Set("Location", f.srv.URL+"/account/1")
		w.WriteHeader(http.StatusCreated)
		writeJSON(map[string]any{"status": "valid"})
	case r.URL.Path == "/new-order":
		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
			Profile     string                         `json:"profile"`
		}
		if err := decodeJWSPayload(r, &req); err != nil {
			f.t.Errorf("new-order payload: %v", err)
		}
		f.mu.Lock()
		f.orders++
		f.gotProfile = req.Profile
		if len(req.Identifiers) == 1 {
			f.gotIDType = req.Identifiers[0].Type
			f.gotIDValue = req.Identifiers[0].Value
		}
		f.authzStatus = "pending"
		f.orderStatus = "pending"
		f.token = fmt.Sprintf("tok-%d", f.orders)
		f.mu.Unlock()
		w.Header().Set("Location", f.srv.URL+"/order/1")
		w.WriteHeader(http.StatusCreated)
		writeJSON(orderJSON())
	case r.URL.Path == "/authz/1":
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(map[string]any{
			"status":     f.authzStatus,
			"identifier": map[string]string{"type": f.gotIDType, "value": f.gotIDValue},
			"challenges": []map[string]string{{
				"type":   "http-01",
				"url":    f.srv.URL + "/chal/1",
				"token":  f.token,
				"status": f.authzStatus,
			}},
		})
	case r.URL.Path == "/chal/1":
		if err := f.validateChallenge(); err != nil {
			f.t.Errorf("challenge validation: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.authzStatus = "valid"
		f.orderStatus = "ready"
		f.mu.Unlock()
		writeJSON(map[string]any{"type": "http-01", "status": "valid", "token": f.token})
	case r.URL.Path == "/order/1":
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Location", f.srv.URL+"/order/1")
		writeJSON(orderJSON())
	case r.URL.Path == "/finalize/1":
		var req struct {
			CSR string `json:"csr"`
		}
		if err := decodeJWSPayload(r, &req); err != nil {
			f.t.Errorf("finalize payload: %v", err)
		}
		if err := f.issueCert(req.CSR); err != nil {
			f.t.Errorf("issuing cert: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.orderStatus = "valid"
		f.mu.Unlock()
		w.Header().Set("Location", f.srv.URL+"/order/1")
		writeJSON(orderJSON())
	case r.URL.Path == "/cert/1":
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(f.certPEM)
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// validateChallenge fetches the http-01 challenge response from the
// server under test, standing in for the CA dialing port 80 at the IP
// address being validated.
func (f *fakeIPACME) validateChallenge() error {
	f.mu.Lock()
	token := f.token
	base := f.challengeBase
	f.mu.Unlock()
	res, err := http.Get(base + "/.well-known/acme-challenge/" + token)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(body), token+".") {
		return fmt.Errorf("challenge response %q does not start with %q", body, token+".")
	}
	return nil
}

// issueCert signs a certificate for the CSR (base64url DER), valid for
// six days like a LetsEncrypt shortlived profile certificate.
func (f *fakeIPACME) issueCert(csrB64 string) error {
	csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return err
	}
	if len(csr.IPAddresses) != 1 {
		return fmt.Errorf("CSR has %d IP addresses; want 1", len(csr.IPAddresses))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(6 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return err
	}
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})...)
	f.mu.Lock()
	f.certPEM = buf
	f.mu.Unlock()
	return nil
}

// decodeJWSPayload decodes the payload of a JWS-encoded ACME request
// without verifying its signature.
func decodeJWSPayload(r *http.Request, v any) error {
	var req struct{ Payload string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}
	b, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ipConn is a stub net.Conn whose LocalAddr is the given IP, standing
// in for the accepted TLS connection whose destination address decides
// which certificate to serve.
type ipConn struct {
	net.Conn
	local net.Addr
}

func (c ipConn) LocalAddr() net.Addr { return c.local }

// helloFor returns a ClientHelloInfo as ipCertManager.getCertificate
// would see it for a connection to localIP with the given SNI value.
func helloFor(t *testing.T, localIP, sni string) *tls.ClientHelloInfo {
	t.Helper()
	ip := net.ParseIP(localIP)
	if ip == nil {
		t.Fatalf("bad IP %q", localIP)
	}
	return &tls.ClientHelloInfo{
		ServerName: sni,
		Conn:       ipConn{local: &net.TCPAddr{IP: ip, Port: 443}},
	}
}

// stubCertProvider is a certProvider returning a fixed certificate,
// standing in for the autocert manager handling DNS hostname
// connections.
type stubCertProvider struct {
	cert *tls.Certificate
}

func (p *stubCertProvider) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.cert, nil
		},
	}
}

func (p *stubCertProvider) HTTPHandler(fallback http.Handler) http.Handler { return fallback }

// TestIPCertManager exercises the on-demand issuance flow of
// ipCertManager against a fake ACME CA: certs are ordered for whatever
// IP address a connection arrives on (IPv4 and IPv6), with the
// shortlived profile, answering the http-01 challenge, and reusing the
// on-disk cache.
func TestIPCertManager(t *testing.T) {
	const ip4 = "203.0.113.7"
	const ip6 = "2001:db8::7"
	dir := t.TempDir()
	ca := newFakeIPACME(t)

	m, err := newIPCertManager(dir, "test@example.com", ca.directoryURL(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Serve the manager's HTTP-01 challenge handler like derper's port
	// 80 listener does.
	challengeSrv := httptest.NewServer(m.HTTPHandler(http.NotFoundHandler()))
	defer challengeSrv.Close()
	ca.challengeBase = challengeSrv.URL

	// A connection to the IPv4 address with no SNI mints a cert for it.
	cert, err := m.getCertificate(helloFor(t, ip4, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname(ip4); err != nil {
		t.Errorf("issued cert not valid for %v: %v", ip4, err)
	}
	if got, want := ca.gotProfile, shortlivedProfile; got != want {
		t.Errorf("order profile = %q; want %q", got, want)
	}
	if ca.gotIDType != "ip" || ca.gotIDValue != ip4 {
		t.Errorf("order identifier = %q %q; want %q %q", ca.gotIDType, ca.gotIDValue, "ip", ip4)
	}
	if n := ca.numOrders(); n != 1 {
		t.Errorf("orders created = %d; want 1", n)
	}

	// A connection to the IPv6 address mints a second, separate cert.
	cert6, err := m.getCertificate(helloFor(t, ip6, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert6.Leaf.VerifyHostname(ip6); err != nil {
		t.Errorf("issued cert not valid for %v: %v", ip6, err)
	}
	if ca.gotIDType != "ip" || ca.gotIDValue != ip6 {
		t.Errorf("order identifier = %q %q; want %q %q", ca.gotIDType, ca.gotIDValue, "ip", ip6)
	}
	if n := ca.numOrders(); n != 2 {
		t.Errorf("orders created = %d; want 2", n)
	}

	// An SNI containing the connection's own IP address is served from
	// the cache.
	if _, err := m.getCertificate(helloFor(t, ip4, ip4)); err != nil {
		t.Errorf("getCertificate with matching IP SNI: %v", err)
	}
	if n := ca.numOrders(); n != 2 {
		t.Errorf("orders created after cached hit = %d; want 2", n)
	}

	// An SNI naming some other IP address is rejected.
	if _, err := m.getCertificate(helloFor(t, ip4, "203.0.113.8")); err == nil {
		t.Error("getCertificate with mismatched IP SNI succeeded; want error")
	}

	// A DNS name SNI has no provider to go to here.
	if _, err := m.getCertificate(helloFor(t, ip4, "derp.example.com")); err == nil {
		t.Error("getCertificate with DNS SNI and no next provider succeeded; want error")
	}

	// A second manager over the same cert directory must use the
	// on-disk cache rather than creating more orders.
	m2, err := newIPCertManager(dir, "test@example.com", ca.directoryURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cachedCert, err := m2.getCertificate(helloFor(t, ip4, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := cachedCert.Leaf.VerifyHostname(ip4); err != nil {
		t.Errorf("cached cert not valid for %v: %v", ip4, err)
	}
	if n := ca.numOrders(); n != 2 {
		t.Errorf("orders created after cache reuse = %d; want 2", n)
	}

	// Non-challenge requests go to the fallback handler.
	rec := httptest.NewRecorder()
	m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "fallback")
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/other", nil))
	if got := rec.Body.String(); got != "fallback" {
		t.Errorf("fallback body = %q; want %q", got, "fallback")
	}
}

// TestIPCertManagerNextProvider verifies that connections with a DNS
// name in the SNI are passed through to the next provider.
func TestIPCertManagerNextProvider(t *testing.T) {
	dir := t.TempDir()
	ca := newFakeIPACME(t)
	stubCert := &tls.Certificate{}
	m, err := newIPCertManager(dir, "", ca.directoryURL(), &stubCertProvider{cert: stubCert})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.getCertificate(helloFor(t, "203.0.113.7", "derp.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got != stubCert {
		t.Errorf("DNS SNI returned %p; want the next provider's cert %p", got, stubCert)
	}
	if n := ca.numOrders(); n != 0 {
		t.Errorf("orders created = %d; want 0", n)
	}
}

// TestCertModeIPCertsGating verifies the flag validation around
// --acme-ip-certs and IP address hostnames.
func TestCertModeIPCertsGating(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		host    string
		ipCerts bool
		wantErr string // or empty to expect success
	}{
		{"letsencrypt_ip_no_flag", "letsencrypt", "1.2.3.4", false, "--acme-ip-certs"},
		{"gcp_ip", "gcp", "1.2.3.4", false, "--certmode=gcp requires --hostname to be a DNS name"},
		{"gcp_flag", "gcp", "1.2.3.4", true, "--acme-ip-certs requires --certmode=letsencrypt"},
		{"manual_flag", "manual", "1.2.3.4", true, "--acme-ip-certs requires --certmode=letsencrypt"},
		{"letsencrypt_ip_flag", "letsencrypt", "1.2.3.4", true, ""},
		{"letsencrypt_hostname_flag", "letsencrypt", "derp.example.com", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp, err := certProviderByCertMode(tt.mode, t.TempDir(), tt.host, tt.ipCerts, "", "", "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("certProviderByCertMode(%q, %q, ipCerts=%v) = %v; want success", tt.mode, tt.host, tt.ipCerts, err)
				}
				m, ok := cp.(*ipCertManager)
				if !ok {
					t.Fatalf("provider type = %T; want *ipCertManager", cp)
				}
				wantNext := net.ParseIP(tt.host) == nil
				if gotNext := m.next != nil; gotNext != wantNext {
					t.Errorf("has next provider = %v; want %v", gotNext, wantNext)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("certProviderByCertMode(%q, %q, ipCerts=%v) error = %v; want contains %q",
					tt.mode, tt.host, tt.ipCerts, err, tt.wantErr)
			}
		})
	}
}
