// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/bakedroots"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/util/testenv"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// certStore provides a way to perist and retrieve TLS certificates.
// As of 2023-02-01, we store certs in directories on disk everywhere
// except on Kubernetes, where we use the state store.
type certStore interface {
	// Read returns the cert and key for domain, if they exist and are valid
	// for now. If they're expired, it returns errCertExpired.
	// If they don't exist, it returns ipn.ErrStateNotExist.
	Read(domain string, now time.Time) (*ipnlocal.TLSCertKeyPair, error)
	// ACMEKey returns the value previously stored via WriteACMEKey.
	// It is a PEM encoded ECDSA key.
	ACMEKey() ([]byte, error)
	// WriteACMEKey stores the provided PEM encoded ECDSA key.
	WriteACMEKey([]byte) error
	// WriteTLSCertAndKey writes the cert and key for domain.
	WriteTLSCertAndKey(domain string, cert, key []byte) error
}

var errCertExpired = errors.New("cert expired")

var testX509Roots *x509.CertPool // set non-nil by tests

// certDir returns (creating if needed) the directory in which cached
// cert keypairs are stored.
func certDir(b *ipnlocal.LocalBackend) (string, error) {
	d := b.TailscaleVarRoot()

	// As a workaround for Synology DSM6 not having a "var" directory, use the
	// app's "etc" directory (on a small partition) to hold certs at least.
	// See https://github.com/tailscale/tailscale/issues/4060#issuecomment-1186592251
	if buildfeatures.HasSynology && d == "" && runtime.GOOS == "linux" && distro.Get() == distro.Synology && distro.DSMVersion() == 6 {
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

func (e *extension) getCertStore(b *ipnlocal.LocalBackend) (certStore, error) {
	st := b.Sys().StateStore.Get()
	switch st.(type) {
	case *store.FileStore:
	case *mem.Store:
	default:
		if hostinfo.GetEnvType() == hostinfo.Kubernetes {
			// We're running in Kubernetes with a custom StateStore,
			// use that instead of the cert directory.
			// TODO(maisem): expand this to other environments?
			return certStateStore{StateStore: st}, nil
		}
	}
	dir, err := certDir(b)
	if err != nil {
		return nil, err
	}
	if testX509Roots != nil && !testenv.InTest() {
		panic("use of test hook outside of tests")
	}
	return certFileStore{dir: dir, testRoots: testX509Roots}, nil
}

// certFileStore implements certStore by storing the cert & key files in
// the named directory.
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

func (f certFileStore) Read(domain string, now time.Time) (*ipnlocal.TLSCertKeyPair, error) {
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
	return &ipnlocal.TLSCertKeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cached: true}, nil
}

func (f certFileStore) WriteCert(domain string, cert []byte) error {
	return atomicfile.WriteFile(certFile(f.dir, domain), cert, 0644)
}

func (f certFileStore) WriteKey(domain string, key []byte) error {
	return atomicfile.WriteFile(keyFile(f.dir, domain), key, 0600)
}

func (f certFileStore) WriteTLSCertAndKey(domain string, cert, key []byte) error {
	if err := f.WriteKey(domain, key); err != nil {
		return err
	}
	return f.WriteCert(domain, cert)
}

// certStateStore implements certStore by storing the cert & key files
// in an ipn.StateStore.
type certStateStore struct {
	ipn.StateStore

	// This field allows a test to override the CA root(s) for certificate
	// verification. If nil the default system pool is used.
	testRoots *x509.CertPool
}

// TLSCertKeyReader is an interface implemented by state stores where it
// makes sense to read the TLS cert and key in a single operation that
// can be distinguished from generic state value reads. Currently this
// is only implemented by the kubestore.Store, which, in some cases,
// needs to read cert and key from a non-cached TLS Secret.
type TLSCertKeyReader interface {
	ReadTLSCertAndKey(domain string) ([]byte, []byte, error)
}

func (s certStateStore) Read(domain string, now time.Time) (*ipnlocal.TLSCertKeyPair, error) {
	// If we're using a store that supports atomic reads, use that
	if kr, ok := s.StateStore.(TLSCertKeyReader); ok {
		cert, key, err := kr.ReadTLSCertAndKey(domain)
		if err != nil {
			return nil, err
		}
		if !validCertPEM(domain, key, cert, s.testRoots, now) {
			return nil, errCertExpired
		}
		return &ipnlocal.TLSCertKeyPair{CertPEM: cert, KeyPEM: key, Cached: true}, nil
	}

	// Otherwise fall back to separate reads
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
	return &ipnlocal.TLSCertKeyPair{CertPEM: certPEM, KeyPEM: keyPEM, Cached: true}, nil
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

// TLSCertKeyWriter is an interface implemented by state stores that can
// write the TLS cert and key in a single atomic operation. Currently
// this is only implemented by the kubestore.StoreKube.
type TLSCertKeyWriter interface {
	WriteTLSCertAndKey(domain string, cert, key []byte) error
}

// WriteTLSCertAndKey writes the TLS cert and key for domain to the
// current LocalBackend's StateStore.
func (s certStateStore) WriteTLSCertAndKey(domain string, cert, key []byte) error {
	// If we're using a store that supports atomic writes, use that.
	if aw, ok := s.StateStore.(TLSCertKeyWriter); ok {
		return aw.WriteTLSCertAndKey(domain, cert, key)
	}
	// Otherwise fall back to separate writes for cert and key.
	if err := s.WriteKey(domain, key); err != nil {
		return err
	}
	return s.WriteCert(domain, cert)
}

func keyFile(dir, domain string) string {
	return filepath.Join(dir, strings.Replace(domain, "*.", "wildcard_.", 1)+".key")
}
func certFile(dir, domain string) string {
	return filepath.Join(dir, strings.Replace(domain, "*.", "wildcard_.", 1)+".crt")
}

// getCertPEMCached returns a non-nil keyPair if a cached keypair for
// domain exists in the certStore that is valid at the provided now time.
//
// If the keypair is expired, it returns errCertExpired.
// If the keypair doesn't exist, it returns ipn.ErrStateNotExist.
func getCertPEMCached(cs certStore, domain string, now time.Time) (p *ipnlocal.TLSCertKeyPair, err error) {
	if !validLookingCertDomain(domain) {
		// Before we read files from disk using it, validate it's halfway
		// reasonable looking.
		return nil, fmt.Errorf("invalid domain %q", domain)
	}
	return cs.Read(domain, now)
}

// certRequest generates a CSR for the given domain and optional SANs.
func certRequest(key crypto.Signer, domain string, ext []pkix.Extension) ([]byte, error) {
	dnsNames := []string{domain}
	if base, ok := strings.CutPrefix(domain, "*."); ok {
		// Wildcard cert must also include the base domain as a SAN.
		// This is load-bearing: getCertPEMCached validates certs using
		// the storage key (base domain), which only passes x509 verification
		// if the base domain is in DNSNames.
		dnsNames = append(dnsNames, base)
	}
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: domain},
		DNSNames:        dnsNames,
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
// Attempt to parse the given private key DER block. OpenSSL 0.9.8
// generates PKCS#1 private keys by default, while OpenSSL 1.0.0
// generates PKCS#8 keys. OpenSSL ecparam generates SEC1 EC private keys
// for ECDSA. We try all three.
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

func (e *extension) acmeKey(cs certStore) (crypto.Signer, error) {
	// Lock so two callers don't both generate a key and race on the
	// write.
	e.accountMu.Lock()
	defer e.accountMu.Unlock()

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

func (e *extension) acmeClient(cs certStore) (*xacme.Client, error) {
	key, err := e.acmeKey(cs)
	if err != nil {
		return nil, fmt.Errorf("acmeKey: %w", err)
	}
	// Note: if we add support for additional ACME providers (other than
	// LetsEncrypt), we should make sure that they support ARI extension (see
	// shouldStartDomainRenewalARI).
	return &xacme.Client{
		Key:          key,
		UserAgent:    "tailscaled/" + version.Long(),
		DirectoryURL: envknob.String("TS_DEBUG_ACME_DIRECTORY_URL"),
	}, nil
}

// validCertPEM reports whether the given certificate is valid for
// domain at now.
//
// If roots != nil, it is used instead of the system root pool. This is
// meant to support testing; production code should pass roots == nil.
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
	return validateLeaf(leaf, intermediates, domain, now, roots)
}

// validateLeaf is a helper for [validCertPEM].
//
// If called with roots == nil, it will use the system root pool as well
// as the baked-in roots. If non-nil, only those roots are used.
func validateLeaf(leaf *x509.Certificate, intermediates *x509.CertPool, domain string, now time.Time, roots *x509.CertPool) bool {
	if leaf == nil {
		return false
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		CurrentTime:   now,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil && roots == nil {
		// If validation failed and they specified nil for roots (meaning to use
		// the system roots), then give it another chance to validate using the
		// binary's baked-in roots (LetsEncrypt). See tailscale/tailscale#14690.
		return validateLeaf(leaf, intermediates, domain, now, bakedroots.Get())
	}

	if err == nil {
		return true
	}

	// When pointed at a non-prod ACME server, we don't expect to have the CA
	// in our system or baked-in roots. Verify only throws UnknownAuthorityError
	// after first checking the leaf cert's expiry, hostnames etc, so we know
	// that the only reason for an error is to do with constructing a full chain.
	// Allow this error so that cert caching still works in testing environments.
	if errors.As(err, &x509.UnknownAuthorityError{}) {
		acmeURL := envknob.String("TS_DEBUG_ACME_DIRECTORY_URL")
		if !isDefaultDirectoryURL(acmeURL) {
			return true
		}
	}

	return false
}

func isDefaultDirectoryURL(u string) bool {
	return u == "" || u == xacme.LetsEncryptURL
}
