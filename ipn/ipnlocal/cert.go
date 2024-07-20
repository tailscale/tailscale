// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package ipnlocal

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
	randv2 "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/golang-x-crypto/acme"
	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
	"tailscale.com/util/testenv"
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

	renewMu     sync.Mutex // lock order: acmeMu before renewMu
	renewCertAt = map[string]time.Time{}
)

// certDir returns (creating if needed) the directory in which cached
// cert keypairs are stored.
func (b *LocalBackend) certDir() (string, error) {
	d := b.TailscaleVarRoot()

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

// GetCertPEM gets the TLSCertKeyPair for domain, either from cache or via the
// ACME process. ACME process is used for new domain certs, existing expired
// certs or existing certs that should get renewed due to upcoming expiry.
//
// If a cert is expired, it will be renewed synchronously otherwise it will be
// renewed asynchronously.
func (b *LocalBackend) GetCertPEM(ctx context.Context, domain string) (*TLSCertKeyPair, error) {
	return b.GetCertPEMWithValidity(ctx, domain, 0)
}

// GetCertPEMWithValidity gets the TLSCertKeyPair for domain, either from cache
// or via the ACME process. ACME process is used for new domain certs, existing
// expired certs or existing certs that should get renewed sooner than
// minValidity.
//
// If a cert is expired, or expires sooner than minValidity, it will be renewed
// synchronously. Otherwise it will be renewed asynchronously.
func (b *LocalBackend) GetCertPEMWithValidity(ctx context.Context, domain string, minValidity time.Duration) (*TLSCertKeyPair, error) {
	if !validLookingCertDomain(domain) {
		return nil, errors.New("invalid domain")
	}
	logf := logger.WithPrefix(b.logf, fmt.Sprintf("cert(%q): ", domain))
	now := b.clock.Now()
	traceACME := func(v any) {
		if !acmeDebug() {
			return
		}
		j, _ := json.MarshalIndent(v, "", "\t")
		log.Printf("acme %T: %s", v, j)
	}

	cs, err := b.getCertStore()
	if err != nil {
		return nil, err
	}

	if pair, err := getCertPEMCached(cs, domain, now); err == nil {
		// If we got here, we have a valid unexpired cert.
		// Check whether we should start an async renewal.
		shouldRenew, err := b.shouldStartDomainRenewal(cs, domain, now, pair, minValidity)
		if err != nil {
			logf("error checking for certificate renewal: %v", err)
			// Renewal check failed, but the current cert is valid and not
			// expired, so it's safe to return.
			return pair, nil
		}
		if !shouldRenew {
			return pair, nil
		}
		if minValidity == 0 {
			logf("starting async renewal")
			// Start renewal in the background, return current valid cert.
			go b.getCertPEM(context.Background(), cs, logf, traceACME, domain, now, minValidity)
			return pair, nil
		}
		// If the caller requested a specific validity duration, fall through
		// to synchronous renewal to fulfill that.
		logf("starting sync renewal")
	}

	pair, err := b.getCertPEM(ctx, cs, logf, traceACME, domain, now, minValidity)
	if err != nil {
		logf("getCertPEM: %v", err)
		return nil, err
	}
	return pair, nil
}

// shouldStartDomainRenewal reports whether the domain's cert should be renewed
// based on the current time, the cert's expiry, and the ARI check.
func (b *LocalBackend) shouldStartDomainRenewal(cs certStore, domain string, now time.Time, pair *TLSCertKeyPair, minValidity time.Duration) (bool, error) {
	if minValidity != 0 {
		cert, err := pair.parseCertificate()
		if err != nil {
			return false, fmt.Errorf("parsing certificate: %w", err)
		}
		return cert.NotAfter.Sub(now) < minValidity, nil
	}
	renewMu.Lock()
	defer renewMu.Unlock()
	if renewAt, ok := renewCertAt[domain]; ok {
		return now.After(renewAt), nil
	}

	renewTime, err := b.domainRenewalTimeByARI(cs, pair)
	if err != nil {
		// Log any ARI failure and fall back to checking for renewal by expiry.
		b.logf("acme: ARI check failed: %v; falling back to expiry-based check", err)
		renewTime, err = b.domainRenewalTimeByExpiry(pair)
		if err != nil {
			return false, err
		}
	}

	renewCertAt[domain] = renewTime
	return now.After(renewTime), nil
}

func (b *LocalBackend) domainRenewed(domain string) {
	renewMu.Lock()
	defer renewMu.Unlock()
	delete(renewCertAt, domain)
}

func (b *LocalBackend) domainRenewalTimeByExpiry(pair *TLSCertKeyPair) (time.Time, error) {
	cert, err := pair.parseCertificate()
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}

	certLifetime := cert.NotAfter.Sub(cert.NotBefore)
	if certLifetime < 0 {
		return time.Time{}, fmt.Errorf("negative certificate lifetime %v", certLifetime)
	}

	// Per https://github.com/tailscale/tailscale/issues/8204, check
	// whether we're more than 2/3 of the way through the certificate's
	// lifetime, which is the officially-recommended best practice by Let's
	// Encrypt.
	renewalDuration := certLifetime * 2 / 3
	renewAt := cert.NotBefore.Add(renewalDuration)
	return renewAt, nil
}

func (b *LocalBackend) domainRenewalTimeByARI(cs certStore, pair *TLSCertKeyPair) (time.Time, error) {
	var blocks []*pem.Block
	rest := pair.CertPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return time.Time{}, fmt.Errorf("parsing certificate PEM")
		}
		blocks = append(blocks, block)
	}
	if len(blocks) < 1 {
		return time.Time{}, fmt.Errorf("could not parse certificate chain from certStore, got %d PEM block(s)", len(blocks))
	}
	ac, err := acmeClient(cs)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	ri, err := ac.FetchRenewalInfo(ctx, blocks[0].Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch renewal info from ACME server: %w", err)
	}
	if acmeDebug() {
		b.logf("acme: ARI response: %+v", ri)
	}

	// Select a random time in the suggested window and renew if that time has
	// passed. Time is randomized per recommendation in
	// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/
	start, end := ri.SuggestedWindow.Start, ri.SuggestedWindow.End
	renewTime := start.Add(randv2.N(end.Sub(start)))
	return renewTime, nil
}

// certStore provides a way to perist and retrieve TLS certificates.
// As of 2023-02-01, we use store certs in directories on disk everywhere
// except on Kubernetes, where we use the state store.
type certStore interface {
	// Read returns the cert and key for domain, if they exist and are valid
	// for now. If they're expired, it returns errCertExpired.
	// If they don't exist, it returns ipn.ErrStateNotExist.
	Read(domain string, now time.Time) (*TLSCertKeyPair, error)
	// WriteCert writes the cert for domain.
	WriteCert(domain string, cert []byte) error
	// WriteKey writes the key for domain.
	WriteKey(domain string, key []byte) error
	// ACMEKey returns the value previously stored via WriteACMEKey.
	// It is a PEM encoded ECDSA key.
	ACMEKey() ([]byte, error)
	// WriteACMEKey stores the provided PEM encoded ECDSA key.
	WriteACMEKey([]byte) error
}

var errCertExpired = errors.New("cert expired")

var testX509Roots *x509.CertPool // set non-nil by tests

func (b *LocalBackend) getCertStore() (certStore, error) {
	switch b.store.(type) {
	case *store.FileStore:
	case *mem.Store:
	default:
		if hostinfo.GetEnvType() == hostinfo.Kubernetes {
			// We're running in Kubernetes with a custom StateStore,
			// use that instead of the cert directory.
			// TODO(maisem): expand this to other environments?
			return certStateStore{StateStore: b.store}, nil
		}
	}
	dir, err := b.certDir()
	if err != nil {
		return nil, err
	}
	if testX509Roots != nil && !testenv.InTest() {
		panic("use of test hook outside of tests")
	}
	return certFileStore{dir: dir, testRoots: testX509Roots}, nil
}

// certFileStore implements certStore by storing the cert & key files in the named directory.
type certFileStore struct {
	dir string

	// This field allows a test to override the CA root(s) for certificate
	// verification. If nil the default system pool is used.
	testRoots *x509.CertPool
}

const acmePEMName = "acme-account.key.pem"

func (f certFileStore) ACMEKey() ([]byte, error) {
	pemName := filepath.Join(f.dir, acmePEMName)
	v, err := os.ReadFile(pemName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ipn.ErrStateNotExist
		}
		return nil, err
	}
	return v, nil
}

func (f certFileStore) WriteACMEKey(b []byte) error {
	pemName := filepath.Join(f.dir, acmePEMName)
	return atomicfile.WriteFile(pemName, b, 0600)
}

func (f certFileStore) Read(domain string, now time.Time) (*TLSCertKeyPair, error) {
	certPEM, err := os.ReadFile(certFile(f.dir, domain))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ipn.ErrStateNotExist
		}
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile(f.dir, domain))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ipn.ErrStateNotExist
		}
		return nil, err
	}
	if !validCertPEM(domain, keyPEM, certPEM, f.testRoots, now) {
		return nil, errCertExpired
	}
	return &TLSCertKeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cached: true}, nil
}

func (f certFileStore) WriteCert(domain string, cert []byte) error {
	return atomicfile.WriteFile(certFile(f.dir, domain), cert, 0644)
}

func (f certFileStore) WriteKey(domain string, key []byte) error {
	return atomicfile.WriteFile(keyFile(f.dir, domain), key, 0600)
}

// certStateStore implements certStore by storing the cert & key files in an ipn.StateStore.
type certStateStore struct {
	ipn.StateStore

	// This field allows a test to override the CA root(s) for certificate
	// verification. If nil the default system pool is used.
	testRoots *x509.CertPool
}

func (s certStateStore) Read(domain string, now time.Time) (*TLSCertKeyPair, error) {
	certPEM, err := s.ReadState(ipn.StateKey(domain + ".crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := s.ReadState(ipn.StateKey(domain + ".key"))
	if err != nil {
		return nil, err
	}
	if !validCertPEM(domain, keyPEM, certPEM, s.testRoots, now) {
		return nil, errCertExpired
	}
	return &TLSCertKeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cached: true}, nil
}

func (s certStateStore) WriteCert(domain string, cert []byte) error {
	return ipn.WriteState(s.StateStore, ipn.StateKey(domain+".crt"), cert)
}

func (s certStateStore) WriteKey(domain string, key []byte) error {
	return ipn.WriteState(s.StateStore, ipn.StateKey(domain+".key"), key)
}

func (s certStateStore) ACMEKey() ([]byte, error) {
	return s.ReadState(ipn.StateKey(acmePEMName))
}

func (s certStateStore) WriteACMEKey(key []byte) error {
	return ipn.WriteState(s.StateStore, ipn.StateKey(acmePEMName), key)
}

// TLSCertKeyPair is a TLS public and private key, and whether they were obtained
// from cache or freshly obtained.
type TLSCertKeyPair struct {
	CertPEM []byte // public key, in PEM form
	KeyPEM  []byte // private key, in PEM form
	Cached  bool   // whether result came from cache
}

func (kp TLSCertKeyPair) parseCertificate() (*x509.Certificate, error) {
	block, _ := pem.Decode(kp.CertPEM)
	if block == nil {
		return nil, fmt.Errorf("error parsing certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, not a CERTIFICATE", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func keyFile(dir, domain string) string  { return filepath.Join(dir, domain+".key") }
func certFile(dir, domain string) string { return filepath.Join(dir, domain+".crt") }

// getCertPEMCached returns a non-nil keyPair if a cached keypair for domain
// exists on disk in dir that is valid at the provided now time.
//
// If the keypair is expired, it returns errCertExpired.
// If the keypair doesn't exist, it returns ipn.ErrStateNotExist.
func getCertPEMCached(cs certStore, domain string, now time.Time) (p *TLSCertKeyPair, err error) {
	if !validLookingCertDomain(domain) {
		// Before we read files from disk using it, validate it's halfway
		// reasonable looking.
		return nil, fmt.Errorf("invalid domain %q", domain)
	}
	return cs.Read(domain, now)
}

func (b *LocalBackend) getCertPEM(ctx context.Context, cs certStore, logf logger.Logf, traceACME func(any), domain string, now time.Time, minValidity time.Duration) (*TLSCertKeyPair, error) {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	// In case this method was triggered multiple times in parallel (when
	// serving incoming requests), check whether one of the other goroutines
	// already renewed the cert before us.
	if p, err := getCertPEMCached(cs, domain, now); err == nil {
		// shouldStartDomainRenewal caches its result so it's OK to call this
		// frequently.
		shouldRenew, err := b.shouldStartDomainRenewal(cs, domain, now, p, minValidity)
		if err != nil {
			logf("error checking for certificate renewal: %v", err)
		} else if !shouldRenew {
			return p, nil
		}
	} else if !errors.Is(err, ipn.ErrStateNotExist) && !errors.Is(err, errCertExpired) {
		return nil, err
	}

	ac, err := acmeClient(cs)
	if err != nil {
		return nil, err
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
	st := b.StatusWithoutPeers()
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

				// Do a best-effort lookup to see if we've already created this DNS name
				// in a previous attempt. Don't burn too much time on it, though. Worst
				// case we ask the server to create something that already exists.
				var resolver net.Resolver
				lookupCtx, lookupCancel := context.WithTimeout(ctx, 500*time.Millisecond)
				txts, _ := resolver.LookupTXT(lookupCtx, key)
				lookupCancel()
				if slices.Contains(txts, rec) {
					logf("TXT record already existed")
				} else {
					logf("starting SetDNS call...")
					err = b.SetDNS(ctx, key, rec)
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
	if err := cs.WriteKey(domain, privPEM.Bytes()); err != nil {
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
	if err := cs.WriteCert(domain, certPEM.Bytes()); err != nil {
		return nil, err
	}
	b.domainRenewed(domain)

	return &TLSCertKeyPair{CertPEM: certPEM.Bytes(), KeyPEM: privPEM.Bytes()}, nil
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

func acmeKey(cs certStore) (crypto.Signer, error) {
	if v, err := cs.ACMEKey(); err == nil {
		priv, _ := pem.Decode(v)
		if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
			return nil, errors.New("acme/autocert: invalid account key found in cache")
		}
		return parsePrivateKey(priv.Bytes)
	} else if !errors.Is(err, ipn.ErrStateNotExist) {
		return nil, err
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var pemBuf bytes.Buffer
	if err := encodeECDSAKey(&pemBuf, privKey); err != nil {
		return nil, err
	}
	if err := cs.WriteACMEKey(pemBuf.Bytes()); err != nil {
		return nil, err
	}
	return privKey, nil
}

func acmeClient(cs certStore) (*acme.Client, error) {
	key, err := acmeKey(cs)
	if err != nil {
		return nil, fmt.Errorf("acmeKey: %w", err)
	}
	// Note: if we add support for additional ACME providers (other than
	// LetsEncrypt), we should make sure that they support ARI extension (see
	// shouldStartDomainRenewalARI).
	return &acme.Client{
		Key:       key,
		UserAgent: "tailscaled/" + version.Long(),
	}, nil
}

// validCertPEM reports whether the given certificate is valid for domain at now.
//
// If roots != nil, it is used instead of the system root pool. This is meant
// to support testing, and production code should pass roots == nil.
func validCertPEM(domain string, keyPEM, certPEM []byte, roots *x509.CertPool, now time.Time) bool {
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
		Roots:         roots,
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
	if len(st.CertDomains) == 0 {
		return errors.New("your Tailscale account does not support getting TLS certs")
	}
	return fmt.Errorf("invalid domain %q; must be one of %q", domain, st.CertDomains)
}
