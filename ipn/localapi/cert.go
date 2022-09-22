// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios && !android && !js
// +build !ios,!android,!js

package localapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/logger"
	"tailscale.com/util/strs"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// Process-wide cache. (A new *Handler is created per connection,
// effectively per request)
var (
	// acmeMu guards all ACME operations, so concurrent requests
	// for certs don't slam ACME. The first will go through and
	// populate the on-disk cache and the rest should use that.
	acmeMu sync.Mutex

	renewMu        sync.Mutex // lock order: don't hold acmeMu and renewMu at the same time
	lastRenewCheck = map[string]time.Time{}
)

func (h *Handler) certDir() (string, error) {
	d := h.b.TailscaleVarRoot()

	// As a workaround for Synology DSM6 not having a "var" directory, use the
	// app's "etc" directory (on a small partition) to hold certs at least.
	// See https://github.com/tailscale/tailscale/issues/4060#issuecomment-1186592251
	if d == "" && runtime.GOOS == "linux" && distro.Get() == distro.Synology && distro.DSMVersion() == 6 {
		d = "/var/packages/Tailscale/etc" // base; we append "certs" below
	}
	if d == "" {
		return "", errors.New("no TailscaleVarRoot")
	}
	full := filepath.Join(d, "certs")
	if err := os.MkdirAll(full, 0700); err != nil {
		return "", err
	}
	return full, nil
}

var acmeDebug = envknob.RegisterBool("TS_DEBUG_ACME")

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite && !h.PermitCert {
		http.Error(w, "cert access denied", http.StatusForbidden)
		return
	}
	dir, err := h.certDir()
	if err != nil {
		h.logf("certDir: %v", err)
		http.Error(w, "failed to get cert dir", 500)
		return
	}

	domain, ok := strs.CutPrefix(r.URL.Path, "/localapi/v0/cert/")
	if !ok {
		http.Error(w, "internal handler config wired wrong", 500)
		return
	}
	if !validLookingCertDomain(domain) {
		http.Error(w, "invalid domain", 400)
		return
	}
	now := time.Now()
	logf := logger.WithPrefix(h.logf, fmt.Sprintf("cert(%q): ", domain))
	traceACME := func(v any) {
		if !acmeDebug() {
			return
		}
		j, _ := json.MarshalIndent(v, "", "\t")
		log.Printf("acme %T: %s", v, j)
	}

	if pair, ok := h.getCertPEMCached(dir, domain, now); ok {
		future := now.AddDate(0, 0, 14)
		if h.shouldStartDomainRenewal(dir, domain, future) {
			logf("starting async renewal")
			// Start renewal in the background.
			go h.getCertPEM(context.Background(), logf, traceACME, dir, domain, future)
		}
		serveKeyPair(w, r, pair)
		return
	}

	pair, err := h.getCertPEM(r.Context(), logf, traceACME, dir, domain, now)
	if err != nil {
		logf("getCertPEM: %v", err)
		http.Error(w, fmt.Sprint(err), 500)
		return
	}
	serveKeyPair(w, r, pair)
}

func (h *Handler) shouldStartDomainRenewal(dir, domain string, future time.Time) bool {
	renewMu.Lock()
	defer renewMu.Unlock()
	now := time.Now()
	if last, ok := lastRenewCheck[domain]; ok && now.Sub(last) < time.Minute {
		// We checked very recently. Don't bother reparsing &
		// validating the x509 cert.
		return false
	}
	lastRenewCheck[domain] = now
	_, ok := h.getCertPEMCached(dir, domain, future)
	return !ok
}

func serveKeyPair(w http.ResponseWriter, r *http.Request, p *keyPair) {
	w.Header().Set("Content-Type", "text/plain")
	switch r.URL.Query().Get("type") {
	case "", "crt", "cert":
		w.Write(p.certPEM)
	case "key":
		w.Write(p.keyPEM)
	case "pair":
		w.Write(p.keyPEM)
		w.Write(p.certPEM)
	default:
		http.Error(w, `invalid type; want "cert" (default), "key", or "pair"`, 400)
	}
}

type keyPair struct {
	certPEM []byte
	keyPEM  []byte
	cached  bool
}

func keyFile(dir, domain string) string  { return filepath.Join(dir, domain+".key") }
func certFile(dir, domain string) string { return filepath.Join(dir, domain+".crt") }

// getCertPEMCached returns a non-nil keyPair and true if a cached
// keypair for domain exists on disk in dir that is valid at the
// provided now time.
func (h *Handler) getCertPEMCached(dir, domain string, now time.Time) (p *keyPair, ok bool) {
	if !validLookingCertDomain(domain) {
		// Before we read files from disk using it, validate it's halfway
		// reasonable looking.
		return nil, false
	}
	if keyPEM, err := os.ReadFile(keyFile(dir, domain)); err == nil {
		certPEM, _ := os.ReadFile(certFile(dir, domain))
		if validCertPEM(domain, keyPEM, certPEM, now) {
			return &keyPair{certPEM: certPEM, keyPEM: keyPEM, cached: true}, true
		}
	}
	return nil, false
}

func (h *Handler) getCertPEM(ctx context.Context, logf logger.Logf, traceACME func(any), dir, domain string, now time.Time) (*keyPair, error) {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	if p, ok := h.getCertPEMCached(dir, domain, now); ok {
		return p, nil
	}

	key, err := acmeKey(dir)
	if err != nil {
		return nil, fmt.Errorf("acmeKey: %w", err)
	}
	ac := &acme.Client{
		Key:       key,
		UserAgent: "tailscaled/" + version.Long,
	}

	a, err := ac.GetReg(ctx, "" /* pre-RFC param */)
	switch {
	case err == nil:
		// Great, already registered.
		logf("already had ACME account.")
	case err == acme.ErrNoAccount:
		a, err = ac.Register(ctx, new(acme.Account), acme.AcceptTOS)
		if err == acme.ErrAccountAlreadyExists {
			// Potential race. Double check.
			a, err = ac.GetReg(ctx, "" /* pre-RFC param */)
		}
		if err != nil {
			return nil, fmt.Errorf("acme.Register: %w", err)
		}
		logf("registered ACME account.")
		traceACME(a)
	default:
		return nil, fmt.Errorf("acme.GetReg: %w", err)

	}
	if a.Status != acme.StatusValid {
		return nil, fmt.Errorf("unexpected ACME account status %q", a.Status)
	}

	// Before hitting LetsEncrypt, see if this is a domain that Tailscale will do DNS challenges for.
	st := h.b.StatusWithoutPeers()
	if err := checkCertDomain(st, domain); err != nil {
		return nil, err
	}

	order, err := ac.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, err
	}
	traceACME(order)

	for _, aurl := range order.AuthzURLs {
		az, err := ac.GetAuthorization(ctx, aurl)
		if err != nil {
			return nil, err
		}
		traceACME(az)
		for _, ch := range az.Challenges {
			if ch.Type == "dns-01" {
				rec, err := ac.DNS01ChallengeRecord(ch.Token)
				if err != nil {
					return nil, err
				}
				key := "_acme-challenge." + domain

				var resolver net.Resolver
				var ok bool
				txts, _ := resolver.LookupTXT(ctx, key)
				for _, txt := range txts {
					if txt == rec {
						ok = true
						logf("TXT record already existed")
						break
					}
				}
				if !ok {
					logf("starting SetDNS call...")
					err = h.b.SetDNS(ctx, key, rec)
					if err != nil {
						return nil, fmt.Errorf("SetDNS %q => %q: %w", key, rec, err)
					}
					logf("did SetDNS")
				}

				chal, err := ac.Accept(ctx, ch)
				if err != nil {
					return nil, fmt.Errorf("Accept: %v", err)
				}
				traceACME(chal)
				break
			}
		}
	}

	orderURI := order.URI
	order, err = ac.WaitOrder(ctx, orderURI)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if oe, ok := err.(*acme.OrderError); ok {
			logf("acme: WaitOrder: OrderError status %q", oe.Status)
		} else {
			logf("acme: WaitOrder error: %v", err)
		}
		return nil, err
	}
	traceACME(order)

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var privPEM bytes.Buffer
	if err := encodeECDSAKey(&privPEM, certPrivKey); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile(dir, domain), privPEM.Bytes(), 0600); err != nil {
		return nil, err
	}

	csr, err := certRequest(certPrivKey, domain, nil)
	if err != nil {
		return nil, err
	}

	logf("requesting cert...")
	der, _, err := ac.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("CreateOrder: %v", err)
	}
	logf("got cert")

	var certPEM bytes.Buffer
	for _, b := range der {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&certPEM, pb); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(certFile(dir, domain), certPEM.Bytes(), 0644); err != nil {
		return nil, err
	}

	return &keyPair{certPEM: certPEM.Bytes(), keyPEM: privPEM.Bytes()}, nil
}

// certRequest generates a CSR for the given common name cn and optional SANs.
func certRequest(key crypto.Signer, cn string, ext []pkix.Extension, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        san,
		ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

// parsePrivateKey is a copy of x/crypto/acme's parsePrivateKey.
//
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Inspired by parsePrivateKey in crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/autocert: unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}

func acmeKey(dir string) (crypto.Signer, error) {
	pemName := filepath.Join(dir, "acme-account.key.pem")
	if v, err := os.ReadFile(pemName); err == nil {
		priv, _ := pem.Decode(v)
		if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
			return nil, errors.New("acme/autocert: invalid account key found in cache")
		}
		return parsePrivateKey(priv.Bytes)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var pemBuf bytes.Buffer
	if err := encodeECDSAKey(&pemBuf, privKey); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pemName, pemBuf.Bytes(), 0600); err != nil {
		return nil, err
	}
	return privKey, nil
}

func validCertPEM(domain string, keyPEM, certPEM []byte, now time.Time) bool {
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return false
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false
	}
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	for i, certDER := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return false
		}
		if i == 0 {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	if leaf == nil {
		return false
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		CurrentTime:   now,
		Intermediates: intermediates,
	})
	return err == nil
}

// validLookingCertDomain reports whether name looks like a valid domain name that
// we might be able to get a cert for.
//
// It's a light check primarily for double checking before it's used
// as part of a filesystem path. The actual validation happens in checkCertDomain.
func validLookingCertDomain(name string) bool {
	if name == "" ||
		strings.Contains(name, "..") ||
		strings.ContainsAny(name, ":/\\\x00") ||
		!strings.Contains(name, ".") {
		return false
	}
	return true
}

func checkCertDomain(st *ipnstate.Status, domain string) error {
	if domain == "" {
		return errors.New("missing domain name")
	}
	for _, d := range st.CertDomains {
		if d == domain {
			return nil
		}
	}
	// Transitional way while server doesn't yet populate CertDomains: also permit the client
	// attempting Self.DNSName.
	okay := st.CertDomains[:len(st.CertDomains):len(st.CertDomains)]
	if st.Self != nil {
		if v := strings.Trim(st.Self.DNSName, "."); v != "" {
			if v == domain {
				return nil
			}
			okay = append(okay, v)
		}
	}
	switch len(okay) {
	case 0:
		return errors.New("your Tailscale account does not support getting TLS certs")
	case 1:
		return fmt.Errorf("invalid domain %q; only %q is permitted", domain, okay[0])
	default:
		return fmt.Errorf("invalid domain %q; must be one of %q", domain, okay)
	}
}
