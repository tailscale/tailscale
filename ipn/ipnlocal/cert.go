// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

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
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/bakedroots"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/acme"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/testenv"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

func init() {
	RegisterC2N("GET /tls-cert-status", handleC2NTLSCertStatus)
	hookCertRefreshLoop.Set(certRefreshLoop)
}

// Process-wide cache. (A new *Handler is created per connection,
// effectively per request)
var (
	// acmeMu guards all ACME operations, so concurrent requests
	// for certs don't slam ACME. The first will go through and
	// populate the on-disk cache and the rest should use that.
	acmeMu syncs.Mutex

	renewMu     syncs.Mutex // lock order: acmeMu before renewMu
	renewCertAt = map[string]time.Time{}
)

var (
	metricACMEDNS01Start       = clientmetric.NewCounter("cert_acme_dns01_start")
	metricACMEDNS01Success     = clientmetric.NewCounter("cert_acme_dns01_success")
	metricACMEDNS01Failure     = clientmetric.NewCounter("cert_acme_dns01_failure")
	metricACMETLSALPN01Start   = clientmetric.NewCounter("cert_acme_tls_alpn01_start")
	metricACMETLSALPN01Success = clientmetric.NewCounter("cert_acme_tls_alpn01_success")
	metricACMETLSALPN01Failure = clientmetric.NewCounter("cert_acme_tls_alpn01_failure")
)

// certPendingWarnable fires while ACME is fetching a TLS certificate for
// which no usable cached copy exists (initial issuance or after the cached
// cert has expired). Async renewal of a still-valid cert does not fire it.
var certPendingWarnable = health.Register(&health.Warnable{
	Code:     tsconst.HealthWarnableTLSCertPending,
	Title:    "Fetching TLS certificate",
	Severity: health.SeverityLow,
	Text: func(args health.Args) string {
		return fmt.Sprintf("Fetching TLS certificate via ACME for: %s", args[health.ArgDomains])
	},
})

type acmeChallengeType string

const (
	acmeChallengeDNS01     acmeChallengeType = "dns-01"
	acmeChallengeTLSALPN01 acmeChallengeType = "tls-alpn-01"
)

// serveTLSNextProtos returns the baseline ALPN protocols for ordinary Serve
// TLS traffic. ACME tls-alpn-01 is intentionally not advertised here; it is
// added dynamically by serveTLSConfig only while a matching challenge
// certificate is pending.
func serveTLSNextProtos() []string {
	return []string{"h2", "http/1.1"}
}

// getACMETLSALPNCert returns the short-lived ACME challenge certificate for
// hi.ServerName. The ok result reports whether hi offered acme-tls/1 and an
// ACME order is actively waiting on that challenge for hi.ServerName.
func (b *LocalBackend) getACMETLSALPNCert(hi *tls.ClientHelloInfo) (cert *tls.Certificate, ok bool) {
	if hi == nil || hi.ServerName == "" || !slices.Contains(hi.SupportedProtos, acme.ALPNProto) {
		return nil, false
	}
	cert, ok = b.pendingACMETLSALPNCerts.Load(hi.ServerName)
	return cert, ok
}

// getACMETLSALPNProto reports whether serveTLSConfig should advertise an ACME
// ALPN protocol for this ClientHello. The proto result is the protocol to
// advertise, and ok reports whether hi offered acme-tls/1 and an ACME order is
// actively waiting on that challenge for hi.ServerName. It is separate from
// getACMETLSALPNCert because Go selects ALPN before calling GetCertificate;
// both hooks must agree for the challenge handshake to complete.
func (b *LocalBackend) getACMETLSALPNProto(hi *tls.ClientHelloInfo) (proto string, ok bool) {
	if _, ok := b.getACMETLSALPNCert(hi); !ok {
		return "", false
	}
	return acme.ALPNProto, true
}

// storeACMETLSALPNCert publishes cert to Serve TLS handshakes for domain until
// the returned cleanup function is called.
func (b *LocalBackend) storeACMETLSALPNCert(domain string, cert *tls.Certificate) (cleanup func()) {
	b.pendingACMETLSALPNCerts.Store(domain, cert)
	return func() {
		b.pendingACMETLSALPNCerts.Delete(domain)
	}
}

// certDir returns (creating if needed) the directory in which cached
// cert keypairs are stored.
func (b *LocalBackend) certDir() (string, error) {
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
//
// The domain must be one of:
//
//   - An exact CertDomain (e.g., "node.ts.net")
//   - A wildcard domain (e.g., "*.node.ts.net")
//   - A bring-your-own Funnel domain referenced by the local serve config
//     (e.g., "foo.com" when ServeConfig.AllowFunnel has "foo.com:443").
//
// The wildcard format requires the NodeAttrDNSSubdomainResolve capability.
// ts.net domains are issued via dns-01 against control's DNS zone; BYO
// Funnel domains are issued via tls-alpn-01 over the same Funnel TLS path
// that serves real traffic.
func (b *LocalBackend) GetCertPEMWithValidity(ctx context.Context, domain string, minValidity time.Duration) (*TLSCertKeyPair, error) {
	b.mu.Lock()
	getCertForTest := b.getCertForTest
	b.mu.Unlock()

	if getCertForTest != nil {
		testenv.AssertInTest()
		return getCertForTest(domain)
	}

	if !validLookingCertDomain(domain) {
		return nil, errors.New("invalid domain")
	}

	certDomain, err := b.resolveCertDomain(domain)
	if err != nil {
		return nil, err
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

	if pair, err := getCertPEMCached(cs, certDomain, now); err == nil {
		if envknob.IsCertShareReadOnlyMode() {
			return pair, nil
		}
		// If we got here, we have a valid unexpired cert.
		// Check whether we should start an async renewal.
		shouldRenew, err := b.shouldStartDomainRenewal(cs, certDomain, now, pair, minValidity)
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
			b.goTracker.Go(func() {
				if _, err := getCertPEM(context.Background(), b, cs, logf, traceACME, certDomain, now, minValidity); err != nil {
					logf("async renewal failed: getCertPem: %v", err)
				}
			})
			return pair, nil
		}
		// If the caller requested a specific validity duration, fall through
		// to synchronous renewal to fulfill that.
		logf("starting sync renewal")
	}

	if envknob.IsCertShareReadOnlyMode() {
		return nil, fmt.Errorf("retrieving cached TLS certificate failed and cert store is configured in read-only mode, not attempting to issue a new certificate: %w", err)
	}

	pair, err := getCertPEM(ctx, b, cs, logf, traceACME, certDomain, now, minValidity)
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

func (b *LocalBackend) shouldUseACMETLSALPN01(domain string, previous *TLSCertKeyPair, logf logger.Logf) bool {
	if isWildcardDomain(domain) {
		logf("acme: using dns-01: tls-alpn-01 does not support wildcard certificates")
		return false
	}
	if !b.hasFunnelForHostPort(domain, 443) {
		logf("acme: using dns-01: Funnel is not enabled for %s:443", domain)
		return false
	}
	if b.isBYOFunnelDomain(domain) {
		// BYO Funnel domain: dns-01 is not a viable path because control
		// does not own the user's DNS zone. Use tls-alpn-01 even on
		// first issuance.
		logf("acme: using tls-alpn-01 (BYO Funnel domain)")
		return true
	}
	if previous == nil {
		logf("acme: using dns-01: no cached certificate for Funnel renewal")
		return false
	}
	logf("acme: using tls-alpn-01")
	return true
}

// isBYOFunnelDomain reports whether domain is a "bring your own" Funnel
// hostname: a domain that is not in the netmap's CertDomains but is
// referenced as a Funnel target on :443 by the local serve config.
// BYO domains can only be issued via tls-alpn-01 because control does
// not own their DNS zone.
func (b *LocalBackend) isBYOFunnelDomain(domain string) bool {
	if domain == "" || isWildcardDomain(domain) {
		return false
	}
	nm := b.NetMapNoPeers()
	if nm != nil && slices.Contains(nm.DNS.CertDomains, domain) {
		return false
	}
	return b.hasFunnelForHostPort(domain, 443)
}

func challengeByType(challenges []*acme.Challenge, typ string) *acme.Challenge {
	for _, ch := range challenges {
		if ch.Type == typ {
			return ch
		}
	}
	return nil
}

func isWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
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

// ConfigureCertsForTest sets a certificate retrieval function to be used by
// this local backend, skipping the usual ACME certificate registration. Should
// only be used in tests.
func (b *LocalBackend) ConfigureCertsForTest(getCert func(hostname string) (*TLSCertKeyPair, error)) {
	testenv.AssertInTest()
	b.mu.Lock()
	b.getCertForTest = getCert
	b.mu.Unlock()
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

func (f certFileStore) WriteTLSCertAndKey(domain string, cert, key []byte) error {
	if err := f.WriteKey(domain, key); err != nil {
		return err
	}
	return f.WriteCert(domain, cert)
}

// certStateStore implements certStore by storing the cert & key files in an ipn.StateStore.
type certStateStore struct {
	ipn.StateStore

	// This field allows a test to override the CA root(s) for certificate
	// verification. If nil the default system pool is used.
	testRoots *x509.CertPool
}

// TLSCertKeyReader is an interface implemented by state stores where it makes
// sense to read the TLS cert and key in a single operation that can be
// distinguished from generic state value reads. Currently this is only implemented
// by the kubestore.Store, which, in some cases, need to read cert and key from a
// non-cached TLS Secret.
type TLSCertKeyReader interface {
	ReadTLSCertAndKey(domain string) ([]byte, []byte, error)
}

func (s certStateStore) Read(domain string, now time.Time) (*TLSCertKeyPair, error) {
	// If we're using a store that supports atomic reads, use that
	if kr, ok := s.StateStore.(TLSCertKeyReader); ok {
		cert, key, err := kr.ReadTLSCertAndKey(domain)
		if err != nil {
			return nil, err
		}
		if !validCertPEM(domain, key, cert, s.testRoots, now) {
			return nil, errCertExpired
		}
		return &TLSCertKeyPair{CertPEM: cert, KeyPEM: key, Cached: true}, nil
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

// TLSCertKeyWriter is an interface implemented by state stores that can write the TLS
// cert and key in a single atomic operation. Currently this is only implemented
// by the kubestore.StoreKube.
type TLSCertKeyWriter interface {
	WriteTLSCertAndKey(domain string, cert, key []byte) error
}

// WriteTLSCertAndKey writes the TLS cert and key for domain to the current
// LocalBackend's StateStore.
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

func keyFile(dir, domain string) string {
	return filepath.Join(dir, strings.Replace(domain, "*.", "wildcard_.", 1)+".key")
}
func certFile(dir, domain string) string {
	return filepath.Join(dir, strings.Replace(domain, "*.", "wildcard_.", 1)+".crt")
}

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

// getCertPem checks if a cert needs to be renewed and if so, renews it.
// domain is the resolved cert domain (e.g., "*.node.ts.net" for wildcards).
// It can be overridden in tests.
var getCertPEM = func(ctx context.Context, b *LocalBackend, cs certStore, logf logger.Logf, traceACME func(any), domain string, now time.Time, minValidity time.Duration) (*TLSCertKeyPair, error) {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	// In case this method was triggered multiple times in parallel (when
	// serving incoming requests), check whether one of the other goroutines
	// already renewed the cert before us.
	previous, err := getCertPEMCached(cs, domain, now)
	if err == nil {
		// shouldStartDomainRenewal caches its result so it's OK to call this
		// frequently.
		shouldRenew, err := b.shouldStartDomainRenewal(cs, domain, now, previous, minValidity)
		if err != nil {
			logf("error checking for certificate renewal: %v", err)
		} else if !shouldRenew {
			return previous, nil
		}
	} else if !errors.Is(err, ipn.ErrStateNotExist) && !errors.Is(err, errCertExpired) {
		return nil, err
	}

	// If we have no usable cached cert (either nothing on disk, or what is
	// on disk has expired or otherwise failed verification), surface a
	// health warning to the user for the duration of the ACME flow. We
	// don't fire the warning when previous is non-nil because then we have
	// a working cert and the renewal is happening behind the scenes.
	if previous == nil {
		b.setCertPending(domain, true)
		defer b.setCertPending(domain, false)
	}

	ac, err := acmeClient(cs)
	if err != nil {
		return nil, err
	}

	if !isDefaultDirectoryURL(ac.DirectoryURL) {
		logf("acme: using Directory URL %q", ac.DirectoryURL)
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

	// If we have a previous cert, include it in the order. Assuming we're
	// within the ARI renewal window this should exclude us from LE rate
	// limits.
	// Note that this order extension will fail renewals if the ACME account key has changed
	// since the last issuance, see
	// https://github.com/tailscale/tailscale/issues/18251
	var opts []acme.OrderOption
	if previous != nil && !envknob.Bool("TS_DEBUG_ACME_FORCE_RENEWAL") {
		prevCrt, err := previous.parseCertificate()
		if err == nil {
			opts = append(opts, acme.WithOrderReplacesCert(prevCrt))
		}
	}

	issueArgs := acmeCertIssueArgs{
		cs:        cs,
		logf:      logf,
		traceACME: traceACME,
		domain:    domain,
		opts:      opts,
	}
	if b.shouldUseACMETLSALPN01(domain, previous, logf) {
		issueArgs.challengeType = acmeChallengeTLSALPN01
		pair, err := b.issueACMECert(ctx, ac, issueArgs)
		if err == nil {
			return pair, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if b.isBYOFunnelDomain(domain) {
			// BYO domains have no working dns-01 path (control does not
			// own the zone), so surface the tls-alpn-01 error instead of
			// burning an ACME attempt on a guaranteed-to-fail fallback.
			return nil, err
		}
		logf("acme: tls-alpn-01 failed; falling back to dns-01: %v", err)
	}
	issueArgs.challengeType = acmeChallengeDNS01
	return b.issueACMECert(ctx, ac, issueArgs)
}

type acmeCertIssueArgs struct {
	cs            certStore          // certificate and ACME account storage
	logf          logger.Logf        // logs ACME progress and failures
	traceACME     func(any)          // optional hook for logging ACME messages
	domain        string             // certificate domain being issued
	opts          []acme.OrderOption // ACME order options
	challengeType acmeChallengeType  // challenge type to fulfill
}

func (args acmeCertIssueArgs) baseDomain() string { return strings.TrimPrefix(args.domain, "*.") }
func (args acmeCertIssueArgs) isWildcard() bool   { return isWildcardDomain(args.domain) }

func (b *LocalBackend) issueACMECert(ctx context.Context, ac *acme.Client, args acmeCertIssueArgs) (ret *TLSCertKeyPair, err error) {
	if args.traceACME == nil {
		args.traceACME = func(any) {}
	}

	switch args.challengeType {
	case acmeChallengeTLSALPN01:
		metricACMETLSALPN01Start.Add(1)
		defer func() {
			if err == nil {
				metricACMETLSALPN01Success.Add(1)
			} else {
				metricACMETLSALPN01Failure.Add(1)
			}
		}()
	case acmeChallengeDNS01:
		metricACMEDNS01Start.Add(1)
		defer func() {
			if err == nil {
				metricACMEDNS01Success.Add(1)
			} else {
				metricACMEDNS01Failure.Add(1)
			}
		}()
	default:
		return nil, fmt.Errorf("unknown ACME challenge type %q", args.challengeType)
	}

	// For wildcards, we need to authorize both the wildcard and base domain.
	var authzIDs []acme.AuthzID
	if args.isWildcard() {
		authzIDs = []acme.AuthzID{
			{Type: "dns", Value: args.domain},
			{Type: "dns", Value: args.baseDomain()},
		}
	} else {
		authzIDs = []acme.AuthzID{{Type: "dns", Value: args.domain}}
	}
	order, err := ac.AuthorizeOrder(ctx, authzIDs, args.opts...)
	if err != nil {
		return nil, err
	}
	args.traceACME(order)

	for _, aurl := range order.AuthzURLs {
		az, err := ac.GetAuthorization(ctx, aurl)
		if err != nil {
			return nil, err
		}
		args.traceACME(az)
		switch args.challengeType {
		case acmeChallengeTLSALPN01:
			ch := challengeByType(az.Challenges, string(acmeChallengeTLSALPN01))
			if ch == nil {
				return nil, errors.New("tls-alpn-01 challenge not offered")
			}
			cert, err := ac.TLSALPN01ChallengeCert(ch.Token, az.Identifier.Value)
			if err != nil {
				return nil, fmt.Errorf("TLSALPN01ChallengeCert: %w", err)
			}
			cleanup := b.storeACMETLSALPNCert(az.Identifier.Value, &cert)
			defer cleanup()
			chal, err := ac.Accept(ctx, ch)
			if err != nil {
				return nil, fmt.Errorf("Accept: %v", err)
			}
			args.traceACME(chal)
		case acmeChallengeDNS01:
			if err := b.fulfillACMEDNS01Challenge(ctx, ac, az, args.logf, args.traceACME); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown ACME challenge type %q", args.challengeType)
		}
	}

	orderURI := order.URI
	order, err = ac.WaitOrder(ctx, orderURI)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if oe, ok := err.(*acme.OrderError); ok {
			args.logf("acme: WaitOrder: OrderError status %q", oe.Status)
		} else {
			args.logf("acme: WaitOrder error: %v", err)
		}
		return nil, err
	}
	args.traceACME(order)

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var privPEM bytes.Buffer
	if err := encodeECDSAKey(&privPEM, certPrivKey); err != nil {
		return nil, err
	}

	csr, err := certRequest(certPrivKey, args.domain, nil)
	if err != nil {
		return nil, err
	}

	args.logf("requesting cert...")
	args.traceACME(csr)
	der, _, err := ac.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("CreateOrder: %v", err)
	}
	args.logf("got cert")

	var certPEM bytes.Buffer
	for _, b := range der {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&certPEM, pb); err != nil {
			return nil, err
		}
	}
	if err := args.cs.WriteTLSCertAndKey(args.domain, certPEM.Bytes(), privPEM.Bytes()); err != nil {
		return nil, err
	}
	b.domainRenewed(args.domain)

	return &TLSCertKeyPair{CertPEM: certPEM.Bytes(), KeyPEM: privPEM.Bytes()}, nil
}

func (b *LocalBackend) fulfillACMEDNS01Challenge(ctx context.Context, ac *acme.Client, az *acme.Authorization, logf logger.Logf, traceACME func(any)) error {
	for _, ch := range az.Challenges {
		if ch.Type != string(acmeChallengeDNS01) {
			continue
		}
		rec, err := ac.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		// For wildcards, the challenge is on the base domain.
		// e.g., "*.node.ts.net" -> "_acme-challenge.node.ts.net"
		key := "_acme-challenge." + strings.TrimPrefix(az.Identifier.Value, "*.")

		// Do a best-effort lookup to see if we've already created this DNS name
		// in a previous attempt. Don't burn too much time on it, though. Worst
		// case we ask the server to create something that already exists.
		var resolver net.Resolver
		lookupCtx, lookupCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		txts, _ := resolver.LookupTXT(lookupCtx, key)
		lookupCancel()
		if slices.Contains(txts, rec) {
			logf("TXT record already existed for %s", key)
		} else {
			logf("starting SetDNS call for %s...", key)
			err = b.SetDNS(ctx, key, rec)
			if err != nil {
				return fmt.Errorf("SetDNS %q => %q: %w", key, rec, err)
			}
			logf("did SetDNS for %s", key)
		}

		chal, err := ac.Accept(ctx, ch)
		if err != nil {
			return fmt.Errorf("Accept: %v", err)
		}
		traceACME(chal)
		return nil
	}
	return errors.New("dns-01 challenge not offered")
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
		Key:          key,
		UserAgent:    "tailscaled/" + version.Long(),
		DirectoryURL: envknob.String("TS_DEBUG_ACME_DIRECTORY_URL"),
	}, nil
}

// validCertPEM reports whether the given certificate is valid for domain at now.
//
// If roots != nil, it is used instead of the system root pool. This is meant
// to support testing; production code should pass roots == nil.
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
// If called with roots == nil, it will use the system root pool as well as the
// baked-in roots. If non-nil, only those roots are used.
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
	return u == "" || u == acme.LetsEncryptURL
}

// validLookingCertDomain reports whether name looks like a valid domain name that
// we might be able to get a cert for.
//
// It's a light check primarily for double checking before it's used
// as part of a filesystem path. The actual validation happens in resolveCertDomain.
func validLookingCertDomain(name string) bool {
	if name == "" ||
		strings.Contains(name, "..") ||
		strings.ContainsAny(name, ":/\\\x00") ||
		!strings.Contains(name, ".") {
		return false
	}
	// Only allow * as a wildcard prefix "*.domain.tld"
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		if strings.Contains(rest, "*") || !strings.Contains(rest, ".") {
			return false
		}
	} else if strings.Contains(name, "*") {
		return false
	}
	return true
}

// resolveCertDomain validates a domain and returns the cert domain to use.
//
//   - "node.ts.net" -> "node.ts.net" (exact CertDomain match)
//   - "*.node.ts.net" -> "*.node.ts.net" (explicit wildcard, requires NodeAttrDNSSubdomainResolve)
//   - "foo.com" -> "foo.com" (bring-your-own Funnel domain referenced by the
//     local serve config; issued via tls-alpn-01 in getCertPEM)
//
// Subdomain requests like "app.node.ts.net" are rejected; callers should
// request "*.node.ts.net" explicitly for subdomain coverage.
func (b *LocalBackend) resolveCertDomain(domain string) (string, error) {
	if domain == "" {
		return "", errors.New("missing domain name")
	}

	// Read the netmap once to get both CertDomains and capabilities atomically.
	nm := b.NetMapNoPeers()
	if nm == nil {
		return "", errors.New("no netmap available")
	}
	certDomains := nm.DNS.CertDomains
	if len(certDomains) == 0 && !b.isBYOFunnelDomain(domain) {
		return "", errors.New("your Tailscale account does not support getting TLS certs")
	}

	// Wildcard request like "*.node.ts.net".
	if base, ok := strings.CutPrefix(domain, "*."); ok {
		if !nm.AllCaps.Contains(tailcfg.NodeAttrDNSSubdomainResolve) {
			return "", fmt.Errorf("wildcard certificates are not enabled for this node")
		}
		if !slices.Contains(certDomains, base) {
			return "", fmt.Errorf("invalid domain %q; wildcard certificates are not enabled for this domain", domain)
		}
		return domain, nil
	}

	// Exact CertDomain match.
	if slices.Contains(certDomains, domain) {
		return domain, nil
	}

	// Bring-your-own Funnel domain (e.g. "foo.com"). The serve config
	// references the domain as a Funnel target on :443; cert acquisition
	// happens via tls-alpn-01 in getCertPEM.
	if b.isBYOFunnelDomain(domain) {
		return domain, nil
	}

	return "", fmt.Errorf("invalid domain %q; must be one of %q", domain, certDomains)
}

// handleC2NTLSCertStatus returns info about the last TLS certificate issued for the
// provided domain. This can be called by the controlplane to clean up DNS TXT
// records when they're no longer needed by LetsEncrypt.
//
// It does not kick off a cert fetch or async refresh. It only reports anything
// that's already sitting on disk, and only reports metadata about the public
// cert (stuff that'd be the in CT logs anyway).
func handleC2NTLSCertStatus(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	cs, err := b.getCertStore()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "no 'domain'", http.StatusBadRequest)
		return
	}

	ret := &tailcfg.C2NTLSCertInfo{}
	pair, err := getCertPEMCached(cs, domain, b.clock.Now())
	ret.Valid = err == nil
	if err != nil {
		ret.Error = err.Error()
		if errors.Is(err, errCertExpired) {
			ret.Expired = true
		} else if errors.Is(err, ipn.ErrStateNotExist) {
			ret.Missing = true
			ret.Error = "no certificate"
		}
	} else {
		block, _ := pem.Decode(pair.CertPEM)
		if block == nil {
			ret.Error = "invalid PEM"
			ret.Valid = false
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ret.Error = fmt.Sprintf("invalid certificate: %v", err)
				ret.Valid = false
			} else {
				ret.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
				ret.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
			}
		}
	}

	writeJSON(w, ret)
}

// setCertPending sets or clears the in-flight ACME issuance state for
// domain and updates the [certPendingWarnable] to reflect the current set
// of pending domains.
func (b *LocalBackend) setCertPending(domain string, pending bool) {
	b.pendingCertDomainsMu.Lock()
	defer b.pendingCertDomainsMu.Unlock()
	if pending {
		b.pendingCertDomains.Make()
		b.pendingCertDomains.Add(domain)
	} else {
		b.pendingCertDomains.Delete(domain)
	}
	if b.pendingCertDomains.Len() == 0 {
		b.health.SetHealthy(certPendingWarnable)
		return
	}
	b.health.SetUnhealthy(certPendingWarnable, health.Args{
		health.ArgDomains: joinedPendingCertDomainsLocked(b.pendingCertDomains),
	})
}

func joinedPendingCertDomainsLocked(s set.Set[string]) string {
	ds := slicesx.MapKeys(s)
	slices.Sort(ds)
	return strings.Join(ds, ", ")
}

// certRefreshInterval is how often the background loop iterates the set of
// applicable cert domains and pokes the renewal machinery. The loop is
// only started while there's at least one HTTPS Web entry in the
// ServeConfig, so this cadence doesn't tick on idle/mobile nodes.
const certRefreshInterval = time.Hour

// certRefreshLoop periodically iterates the domains configured for Serve or
// Funnel HTTPS and calls GetCertPEM on each. The existing renewal machinery
// in getCertPEM decides whether anything needs to happen (ARI check or
// expiry-based fallback); the loop just ensures it runs even on nodes that
// see no inbound TLS traffic.
//
// The first iteration runs immediately so that a node coming back online
// with stale or absent certs starts ACME within seconds rather than
// waiting a full interval.
//
// Set as [hookCertRefreshLoop] in cert.go's init.
func certRefreshLoop(b *LocalBackend, ctx context.Context) {
	if envknob.IsCertShareReadOnlyMode() {
		b.logf("cert refresh loop: cert-share read-only mode; loop is a no-op")
		return
	}

	b.refreshApplicableCerts(ctx)

	ticker, tickerCh := b.clock.NewTicker(certRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tickerCh:
			b.refreshApplicableCerts(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// refreshApplicableCerts is one iteration of the cert refresh loop.
//
// It enumerates the Serve/Funnel-configured HTTPS hostnames, keeps those
// that [LocalBackend.resolveCertDomain] accepts (CertDomain, wildcard, or
// BYO Funnel domain), and calls [LocalBackend.GetCertPEM] for each. The
// renewal decision is delegated to the existing logic in [getCertPEM].
func (b *LocalBackend) refreshApplicableCerts(ctx context.Context) {
	sc := b.ServeConfig()
	if !sc.Valid() {
		return
	}

	want := set.Set[string]{}
	consider := func(host string) {
		if host == "" {
			return
		}
		if _, err := b.resolveCertDomain(host); err != nil {
			return
		}
		want.Add(host)
	}
	for hp := range sc.Webs() {
		host, _, err := net.SplitHostPort(string(hp))
		if err != nil {
			continue
		}
		consider(host)
	}
	for _, tcp := range sc.TCPs() {
		consider(tcp.TerminateTLS())
	}
	for _, svc := range sc.Services().All() {
		for _, tcp := range svc.TCP().All() {
			consider(tcp.TerminateTLS())
		}
	}
	if want.Len() == 0 {
		return
	}

	for d := range want {
		b.goTracker.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if _, err := b.GetCertPEM(ctx, d); err != nil {
				b.logf("cert refresh: %s: %v", d, err)
			}
		})
	}
}
