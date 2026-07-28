// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/acme"
)

// shortlivedProfile is the ACME certificate profile required by
// LetsEncrypt for IP address certificates. Certificates issued under
// it are valid for about six days.
// See https://letsencrypt.org/docs/profiles/.
const shortlivedProfile = "shortlived"

// ipCertManager is a certProvider that obtains and renews LetsEncrypt
// TLS certificates for the server's IP addresses on demand, using the
// short-lived ACME certificate profile and the HTTP-01 challenge
// served on the derper's plaintext HTTP port.
//
// Clients connecting to an IP address usually send no SNI, so the
// requested IP address is taken from the TCP connection's local
// address. That works for however many IPv4 and IPv6 addresses the
// server has, with no configuration. Clients that do send an IP
// address in the SNI get a certificate only if it matches the
// connection's local address, so a client can never make us request a
// certificate for an address that isn't ours.
//
// Connections with a DNS name in the SNI are passed through to the
// optional next provider (the regular autocert manager for the
// --hostname certificate), if any.
type ipCertManager struct {
	certDir string
	email   string // optional ACME account contact
	client  *acme.Client
	next    certProvider // provider for DNS hostname connections, or nil
	nextTLS *tls.Config  // next.TLSConfig(), or nil

	mu     sync.Mutex
	certs  map[netip.Addr]*ipCertEntry
	tokens map[string]string // HTTP-01 challenge URL path => response body
}

// ipCertEntry is the issuance state for one IP address.
// All fields are guarded by ipCertManager.mu.
type ipCertEntry struct {
	cert *tls.Certificate // current cert with Leaf set, or nil if not yet issued

	flight      chan struct{} // non-nil while an issuance is running; closed when it finishes
	flightErr   error         // result of the last finished issuance
	nextAttempt time.Time     // earliest time of the next issuance attempt, after a failure
	retryDelay  time.Duration // backoff to apply after the next failure
}

// newIPCertManager returns an ipCertManager storing its ACME account
// key and issued certificates in certdir.
//
// If directoryURL is empty, the LetsEncrypt production directory is
// used; tests point it at a fake ACME server. If next is non-nil,
// connections with a DNS name in the SNI are served by it.
func newIPCertManager(certdir, email, directoryURL string, next certProvider) (*ipCertManager, error) {
	if err := os.MkdirAll(certdir, 0700); err != nil {
		return nil, err
	}
	accountKey, err := loadOrCreateAccountKey(filepath.Join(certdir, "acme-account.key"))
	if err != nil {
		return nil, fmt.Errorf("ACME account key: %w", err)
	}
	m := &ipCertManager{
		certDir: certdir,
		email:   email,
		client: &acme.Client{
			Key:          accountKey,
			DirectoryURL: directoryURL,
			UserAgent:    "tailscale-derper",
		},
		next:   next,
		certs:  make(map[netip.Addr]*ipCertEntry),
		tokens: make(map[string]string),
	}
	if next != nil {
		m.nextTLS = next.TLSConfig()
	}
	go m.renewLoop()
	return m, nil
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if pemBytes, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %s", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := atomicfile.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// certPaths returns the cert and key file paths for ip in m.certDir.
// Colons in IPv6 addresses are replaced with dots to keep the names
// filesystem-safe.
func (m *ipCertManager) certPaths(ip netip.Addr) (crtPath, keyPath string) {
	base := strings.ReplaceAll(ip.String(), ":", ".")
	return filepath.Join(m.certDir, base+".crt"), filepath.Join(m.certDir, base+".key")
}

func (m *ipCertManager) TLSConfig() *tls.Config {
	var conf *tls.Config
	if m.nextTLS != nil {
		conf = m.nextTLS.Clone()
	} else {
		conf = &tls.Config{
			NextProtos: []string{
				"http/1.1",
			},
		}
	}
	conf.GetCertificate = m.getCertificate
	return conf
}

// connLocalIP returns the local (server side) IP address of the
// connection that sent the ClientHello.
func connLocalIP(hi *tls.ClientHelloInfo) (netip.Addr, bool) {
	if hi.Conn == nil {
		return netip.Addr{}, false
	}
	ta, ok := hi.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip := ta.AddrPort().Addr().Unmap()
	return ip, ip.IsValid()
}

func (m *ipCertManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	connIP, connIPOK := connLocalIP(hi)
	if hi.ServerName != "" {
		sniIP, err := netip.ParseAddr(hi.ServerName)
		if err != nil {
			// The SNI is a DNS name; let the hostname provider handle it.
			if m.nextTLS != nil && m.nextTLS.GetCertificate != nil {
				return m.nextTLS.GetCertificate(hi)
			}
			return nil, fmt.Errorf("no certificate for hostname %q; this server only serves IP address certificates", hi.ServerName)
		}
		if !connIPOK || sniIP.Unmap() != connIP {
			return nil, fmt.Errorf("requested certificate for IP %v does not match the connection's IP address", sniIP)
		}
	}
	if !connIPOK {
		return nil, errors.New("unable to determine the connection's local IP address")
	}
	ctx := hi.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return m.certForIP(ctx, connIP)
}

// certForIP returns the current certificate for ip, obtaining one
// first if there is no unexpired certificate for it. Concurrent
// callers for the same IP share a single issuance.
func (m *ipCertManager) certForIP(ctx context.Context, ip netip.Addr) (*tls.Certificate, error) {
	m.mu.Lock()
	e := m.entryLocked(ip)
	if e.cert != nil && time.Now().Before(e.cert.Leaf.NotAfter) {
		defer m.mu.Unlock()
		return clipCert(e.cert), nil
	}
	if e.flight == nil && time.Now().Before(e.nextAttempt) {
		m.mu.Unlock()
		return nil, fmt.Errorf("cert issuance for %v failed recently; next attempt no earlier than %v", ip, e.nextAttempt.Format(time.RFC3339))
	}
	flight := m.startFlightLocked(ip, e)
	m.mu.Unlock()

	select {
	case <-flight:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if e.cert == nil {
		return nil, e.flightErr
	}
	return clipCert(e.cert), nil
}

func (m *ipCertManager) entryLocked(ip netip.Addr) *ipCertEntry {
	e, ok := m.certs[ip]
	if !ok {
		e = &ipCertEntry{}
		m.certs[ip] = e
	}
	return e
}

// clipCert returns a shallow copy of cert with a capacity-clamped
// chain so callers can never mutate the manager's long-lived
// certificate.
func clipCert(cert *tls.Certificate) *tls.Certificate {
	certCopy := *cert
	certCopy.Certificate = slices.Clip(certCopy.Certificate)
	return &certCopy
}

// startFlightLocked starts an issuance for ip if none is running and
// returns a channel that is closed when it finishes.
func (m *ipCertManager) startFlightLocked(ip netip.Addr, e *ipCertEntry) chan struct{} {
	if e.flight != nil {
		return e.flight
	}
	done := make(chan struct{})
	e.flight = done
	go func() {
		err := m.issue(ip)
		m.mu.Lock()
		defer m.mu.Unlock()
		e.flight = nil
		e.flightErr = err
		if err != nil {
			if e.retryDelay == 0 {
				e.retryDelay = time.Minute
			}
			e.nextAttempt = time.Now().Add(e.retryDelay)
			e.retryDelay = min(e.retryDelay*2, 30*time.Minute)
			log.Printf("derper: acme: getting cert for %v: %v (next attempt in %v)", ip, err, time.Until(e.nextAttempt).Round(time.Second))
		} else {
			e.retryDelay = 0
			e.nextAttempt = time.Time{}
		}
		close(done)
	}()
	return done
}

// issue obtains a certificate for ip, preferring a still-fresh one
// cached on disk over a new ACME order.
func (m *ipCertManager) issue(ip netip.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if cert, err := m.loadCachedCert(ip); err == nil && !certNeedsRenewal(cert.Leaf) {
		m.mu.Lock()
		m.entryLocked(ip).cert = cert
		m.mu.Unlock()
		log.Printf("derper: acme: loaded cached cert for %v (expires %v)", ip, cert.Leaf.NotAfter)
		return nil
	}
	return m.obtainCert(ctx, ip)
}

// loadCachedCert loads a previously issued certificate for ip from
// disk, if present and still valid.
func (m *ipCertManager) loadCachedCert(ip netip.Addr) (*tls.Certificate, error) {
	crtPath, keyPath := m.certPaths(ip)
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("cached cert is expired or not yet valid (NotAfter %v)", leaf.NotAfter)
	}
	if err := leaf.VerifyHostname(ip.String()); err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &cert, nil
}

// HTTPHandler returns a handler serving HTTP-01 challenge responses on
// the derper's plaintext HTTP port, sending all other requests to the
// next provider's handler, if any, and otherwise to fallback.
func (m *ipCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	if m.next != nil {
		fallback = m.next.HTTPHandler(fallback)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}
		m.mu.Lock()
		response, ok := m.tokens[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, response)
	})
}

func (m *ipCertManager) setToken(path, response string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[path] = response
}

func (m *ipCertManager) deleteToken(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, path)
}

// certNeedsRenewal reports whether leaf has less than a third of its
// lifetime remaining. LetsEncrypt short-lived certs are valid for
// about six days, so renewal happens roughly every four.
func certNeedsRenewal(leaf *x509.Certificate) bool {
	total := leaf.NotAfter.Sub(leaf.NotBefore)
	return time.Until(leaf.NotAfter) < total/3
}

// renewLoop runs for the lifetime of the process, renewing each issued
// certificate as it approaches expiry.
func (m *ipCertManager) renewLoop() {
	for {
		time.Sleep(time.Hour)
		m.mu.Lock()
		now := time.Now()
		for ip, e := range m.certs {
			if e.cert != nil && certNeedsRenewal(e.cert.Leaf) && e.flight == nil && now.After(e.nextAttempt) {
				m.startFlightLocked(ip, e)
			}
		}
		m.mu.Unlock()
	}
}

// obtainCert does one ACME issuance flow for ip: it registers the
// account if needed, orders a short-lived profile certificate for the
// IP address identifier, fulfills the HTTP-01 challenges, and installs
// and caches the issued certificate.
func (m *ipCertManager) obtainCert(ctx context.Context, ip netip.Addr) error {
	ipStr := ip.String()

	var contact []string
	if m.email != "" {
		contact = []string{"mailto:" + m.email}
	}
	_, err := m.client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register: %w", err)
	}

	order, err := m.client.AuthorizeOrder(ctx, acme.IPIDs(ipStr), acme.WithOrderProfile(shortlivedProfile))
	if err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := m.fulfillAuthz(ctx, authzURL); err != nil {
			return err
		}
	}
	order, err = m.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("waiting for order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		IPAddresses: []net.IP{ip.AsSlice()},
	}, certKey)
	if err != nil {
		return err
	}
	der, _, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalizing order: %w", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("parsing issued cert: %w", err)
	}
	if err := leaf.VerifyHostname(ipStr); err != nil {
		return fmt.Errorf("issued cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	var chainPEM []byte
	for _, b := range der {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	crtPath, keyPath := m.certPaths(ip)
	if err := atomicfile.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := atomicfile.WriteFile(crtPath, chainPEM, 0644); err != nil {
		return err
	}

	m.mu.Lock()
	m.entryLocked(ip).cert = &tls.Certificate{
		Certificate: der,
		PrivateKey:  certKey,
		Leaf:        leaf,
	}
	m.mu.Unlock()

	dn := &tailcfg.DERPNode{
		Name:     "custom",
		RegionID: 900,
		HostName: ipStr,
	}
	dnJSON, _ := json.Marshal(dn)
	log.Printf("derper: acme: got cert for %v (expires %v). Configure it in DERPMap using (https://tailscale.com/s/custom-derp):\n  %s", ip, leaf.NotAfter, dnJSON)
	return nil
}

// fulfillAuthz completes the HTTP-01 challenge for one authorization,
// if it is still pending.
func (m *ipCertManager) fulfillAuthz(ctx context.Context, authzURL string) error {
	authz, err := m.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("getting authorization: %w", err)
	}
	if authz.Status != acme.StatusPending {
		return nil
	}
	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return errors.New("authorization offers no http-01 challenge")
	}
	response, err := m.client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}
	path := m.client.HTTP01ChallengePath(challenge.Token)
	m.setToken(path, response)
	defer m.deleteToken(path)
	if _, err := m.client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accepting challenge: %w", err)
	}
	if _, err := m.client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("waiting for authorization: %w", err)
	}
	return nil
}
