// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"bytes"
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
	"log"
	randv2 "math/rand/v2"
	"net"
	"slices"
	"strings"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/testenv"
)

type acmeChallengeType string

const (
	acmeChallengeDNS01     acmeChallengeType = "dns-01"
	acmeChallengeTLSALPN01 acmeChallengeType = "tls-alpn-01"
)

var acmeDebug = envknob.RegisterBool("TS_DEBUG_ACME")

// getACMETLSALPNCert returns the short-lived ACME challenge certificate
// for hi.ServerName. The ok result reports whether hi offered acme-tls/1
// and an ACME order is actively waiting on that challenge for
// hi.ServerName.
func (e *extension) getACMETLSALPNCert(hi *tls.ClientHelloInfo) (cert *tls.Certificate, ok bool) {
	if hi == nil || hi.ServerName == "" || !slices.Contains(hi.SupportedProtos, xacme.ALPNProto) {
		return nil, false
	}
	cert, ok = e.pendingACMETLSALPNCerts.Load(hi.ServerName)
	return cert, ok
}

// getACMETLSALPNProto reports whether serveTLSConfig should advertise
// an ACME ALPN protocol for this ClientHello.
func (e *extension) getACMETLSALPNProto(hi *tls.ClientHelloInfo) (proto string, ok bool) {
	if _, ok := e.getACMETLSALPNCert(hi); !ok {
		return "", false
	}
	return xacme.ALPNProto, true
}

// storeACMETLSALPNCert publishes cert to Serve TLS handshakes for domain
// until the returned cleanup function is called.
func (e *extension) storeACMETLSALPNCert(domain string, cert *tls.Certificate) (cleanup func()) {
	e.pendingACMETLSALPNCerts.Store(domain, cert)
	return func() {
		e.pendingACMETLSALPNCerts.Delete(domain)
	}
}

// getCertPEMWithValidity gets the TLSCertKeyPair for domain, either
// from cache or via ACME. ACME is used for new domain certs, existing
// expired certs, or existing certs that should be renewed sooner than
// minValidity.
func (e *extension) getCertPEMWithValidity(ctx context.Context, b *ipnlocal.LocalBackend, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
	e.mu.Lock()
	getCertForTest := e.getCertForTest
	e.mu.Unlock()

	if getCertForTest != nil {
		testenv.AssertInTest()
		return getCertForTest(domain)
	}

	if !validLookingCertDomain(domain) {
		return nil, errors.New("invalid domain")
	}

	certDomain, err := e.resolveCertDomain(b, domain)
	if err != nil {
		return nil, err
	}
	logf := logger.WithPrefix(b.Logger(), fmt.Sprintf("cert(%q): ", domain))
	now := b.Clock().Now()
	traceACME := func(v any) {
		if !acmeDebug() {
			return
		}
		j, _ := json.MarshalIndent(v, "", "\t")
		log.Printf("acme %T: %s", v, j)
	}

	cs, err := e.getCertStore(b)
	if err != nil {
		return nil, err
	}

	pair, cacheErr := getCertPEMCached(cs, certDomain, now)
	if cacheErr == nil {
		if envknob.IsCertShareReadOnlyMode() {
			return pair, nil
		}
		// If we got here, we have a valid unexpired cert.
		// Check whether we should start an async renewal.
		shouldRenew, err := e.shouldStartDomainRenewal(b, cs, certDomain, now, pair, minValidity)
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
			e.Go(func() {
				if _, err := getCertPEM(context.Background(), e, b, cs, logf, traceACME, certDomain, now, minValidity); err != nil {
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
		return nil, fmt.Errorf("retrieving cached TLS certificate failed and cert store is configured in read-only mode, not attempting to issue a new certificate: %w", cacheErr)
	}

	pair, err = getCertPEM(ctx, e, b, cs, logf, traceACME, certDomain, now, minValidity)
	if err != nil {
		logf("getCertPEM: %v", err)
		return nil, err
	}
	return pair, nil
}

// shouldStartDomainRenewal reports whether the domain's cert should be
// renewed based on the current time, the cert's expiry, and the ARI
// check.
func (e *extension) shouldStartDomainRenewal(b *ipnlocal.LocalBackend, cs certStore, domain string, now time.Time, pair *ipnlocal.TLSCertKeyPair, minValidity time.Duration) (bool, error) {
	if minValidity != 0 {
		cert, err := parseCertificate(pair)
		if err != nil {
			return false, fmt.Errorf("parsing certificate: %w", err)
		}
		return cert.NotAfter.Sub(now) < minValidity, nil
	}
	e.renewMu.Lock()
	defer e.renewMu.Unlock()
	if renewAt, ok := e.renewCertAt[domain]; ok {
		return now.After(renewAt), nil
	}

	renewTime, err := e.domainRenewalTimeByARI(b, cs, pair)
	if err != nil {
		// Log any ARI failure and fall back to checking for renewal by expiry.
		b.Logger()("acme: ARI check failed: %v; falling back to expiry-based check", err)
		renewTime, err = domainRenewalTimeByExpiry(pair)
		if err != nil {
			return false, err
		}
	}

	mak.Set(&e.renewCertAt, domain, renewTime)
	return now.After(renewTime), nil
}

func (e *extension) domainRenewed(domain string) {
	e.renewMu.Lock()
	defer e.renewMu.Unlock()
	delete(e.renewCertAt, domain)
}

func domainRenewalTimeByExpiry(pair *ipnlocal.TLSCertKeyPair) (time.Time, error) {
	cert, err := parseCertificate(pair)
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

func (e *extension) shouldUseACMETLSALPN01(b *ipnlocal.LocalBackend, domain string, previous *ipnlocal.TLSCertKeyPair, logf logger.Logf) bool {
	if isWildcardDomain(domain) {
		logf("acme: using dns-01: tls-alpn-01 does not support wildcard certificates")
		return false
	}
	if !b.HasFunnelForHostPort(domain, 443) {
		logf("acme: using dns-01: Funnel is not enabled for %s:443", domain)
		return false
	}
	if e.isBYOFunnelDomain(b, domain) {
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
func (e *extension) isBYOFunnelDomain(b *ipnlocal.LocalBackend, domain string) bool {
	if domain == "" || isWildcardDomain(domain) {
		return false
	}
	nm := b.NetMapNoPeers()
	if nm != nil && slices.Contains(nm.DNS.CertDomains, domain) {
		return false
	}
	return b.HasFunnelForHostPort(domain, 443)
}

func challengeByType(challenges []*xacme.Challenge, typ string) *xacme.Challenge {
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

func (e *extension) domainRenewalTimeByARI(b *ipnlocal.LocalBackend, cs certStore, pair *ipnlocal.TLSCertKeyPair) (time.Time, error) {
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
	ac, err := e.acmeClient(cs)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ri, err := ac.FetchRenewalInfo(ctx, blocks[0].Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to fetch renewal info from ACME server: %w", err)
	}
	if acmeDebug() {
		b.Logger()("acme: ARI response: %+v", ri)
	}

	// Select a random time in the suggested window and renew if that time has
	// passed. Time is randomized per recommendation in
	// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/
	start, end := ri.SuggestedWindow.Start, ri.SuggestedWindow.End
	renewTime := start.Add(randv2.N(end.Sub(start)))
	return renewTime, nil
}

// getCertPEM checks if a cert needs to be renewed and if so, renews it.
// domain is the resolved cert domain (e.g., "*.node.ts.net" for
// wildcards). It can be overridden in tests.
var getCertPEM = func(ctx context.Context, e *extension, b *ipnlocal.LocalBackend, cs certStore, logf logger.Logf, traceACME func(any), domain string, now time.Time, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
	dm := e.lockDomain(domain)
	dm.Lock()
	defer dm.Unlock()

	// In case this method was triggered multiple times in parallel (when
	// serving incoming requests), check whether one of the other goroutines
	// already renewed the cert before us.
	previous, err := getCertPEMCached(cs, domain, now)
	if err == nil {
		// shouldStartDomainRenewal caches its result so it's OK to call this
		// frequently.
		shouldRenew, err := e.shouldStartDomainRenewal(b, cs, domain, now, previous, minValidity)
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
		e.setCertPending(b, domain, true)
		defer e.setCertPending(b, domain, false)
	}

	ac, err := e.acmeClient(cs)
	if err != nil {
		return nil, err
	}

	if !isDefaultDirectoryURL(ac.DirectoryURL) {
		logf("acme: using Directory URL %q", ac.DirectoryURL)
	}

	a, err := e.ensureAccount(ctx, ac, logf, traceACME)
	if err != nil {
		return nil, err
	}
	if a.Status != xacme.StatusValid {
		return nil, fmt.Errorf("unexpected ACME account status %q", a.Status)
	}

	// If we have a previous cert, include it in the order. Assuming we're
	// within the ARI renewal window this should exclude us from LE rate
	// limits.
	// Note that this order extension will fail renewals if the ACME account key has changed
	// since the last issuance, see
	// https://github.com/tailscale/tailscale/issues/18251
	var opts []xacme.OrderOption
	if previous != nil && !envknob.Bool("TS_DEBUG_ACME_FORCE_RENEWAL") {
		prevCrt, err := parseCertificate(previous)
		if err == nil {
			opts = append(opts, xacme.WithOrderReplacesCert(prevCrt))
		}
	}

	issueArgs := acmeCertIssueArgs{
		cs:        cs,
		logf:      logf,
		traceACME: traceACME,
		domain:    domain,
		opts:      opts,
	}
	if e.shouldUseACMETLSALPN01(b, domain, previous, logf) {
		issueArgs.challengeType = acmeChallengeTLSALPN01
		pair, err := e.issueACMECert(ctx, b, ac, issueArgs)
		if err == nil {
			return pair, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if e.isBYOFunnelDomain(b, domain) {
			// BYO domains have no working dns-01 path (control does not
			// own the zone), so surface the tls-alpn-01 error instead of
			// burning an ACME attempt on a guaranteed-to-fail fallback.
			return nil, err
		}
		logf("acme: tls-alpn-01 failed; falling back to dns-01: %v", err)
	}
	issueArgs.challengeType = acmeChallengeDNS01
	return e.issueACMECert(ctx, b, ac, issueArgs)
}

// ensureAccount returns a valid ACME account, registering one if
// needed. Locked so two first-time issuances don't both create one.
func (e *extension) ensureAccount(ctx context.Context, ac *xacme.Client, logf logger.Logf, traceACME func(any)) (*xacme.Account, error) {
	e.accountMu.Lock()
	defer e.accountMu.Unlock()
	a, err := ac.GetReg(ctx, "" /* pre-RFC param */)
	switch {
	case err == nil:
		logf("already had ACME account.")
		return a, nil
	case err == xacme.ErrNoAccount:
		a, err = ac.Register(ctx, new(xacme.Account), xacme.AcceptTOS)
		if err == xacme.ErrAccountAlreadyExists {
			a, err = ac.GetReg(ctx, "" /* pre-RFC param */)
		}
		if err != nil {
			return nil, fmt.Errorf("acme.Register: %w", err)
		}
		logf("registered ACME account.")
		traceACME(a)
		return a, nil
	default:
		return nil, fmt.Errorf("acme.GetReg: %w", err)
	}
}

type acmeCertIssueArgs struct {
	cs            certStore          // certificate and ACME account storage
	logf          logger.Logf        // logs ACME progress and failures
	traceACME     func(any)          // optional hook for logging ACME messages
	domain        string             // certificate domain being issued
	opts          []xacme.OrderOption // ACME order options
	challengeType acmeChallengeType  // challenge type to fulfill
}

func (args acmeCertIssueArgs) baseDomain() string { return strings.TrimPrefix(args.domain, "*.") }
func (args acmeCertIssueArgs) isWildcard() bool   { return isWildcardDomain(args.domain) }

func (e *extension) issueACMECert(ctx context.Context, b *ipnlocal.LocalBackend, ac *xacme.Client, args acmeCertIssueArgs) (ret *ipnlocal.TLSCertKeyPair, err error) {
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
	var authzIDs []xacme.AuthzID
	if args.isWildcard() {
		authzIDs = []xacme.AuthzID{
			{Type: "dns", Value: args.domain},
			{Type: "dns", Value: args.baseDomain()},
		}
	} else {
		authzIDs = []xacme.AuthzID{{Type: "dns", Value: args.domain}}
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
			cleanup := e.storeACMETLSALPNCert(az.Identifier.Value, &cert)
			defer cleanup()
			chal, err := ac.Accept(ctx, ch)
			if err != nil {
				return nil, fmt.Errorf("Accept: %v", err)
			}
			args.traceACME(chal)
		case acmeChallengeDNS01:
			if err := fulfillACMEDNS01Challenge(ctx, b, ac, az, args.logf, args.traceACME); err != nil {
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
		if oe, ok := err.(*xacme.OrderError); ok {
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
	e.domainRenewed(args.domain)

	return &ipnlocal.TLSCertKeyPair{CertPEM: certPEM.Bytes(), KeyPEM: privPEM.Bytes()}, nil
}

func fulfillACMEDNS01Challenge(ctx context.Context, b *ipnlocal.LocalBackend, ac *xacme.Client, az *xacme.Authorization, logf logger.Logf, traceACME func(any)) error {
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

// validLookingCertDomain reports whether name looks like a valid domain
// name that we might be able to get a cert for.
//
// It's a light check primarily for double checking before it's used as
// part of a filesystem path. The actual validation happens in
// resolveCertDomain.
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
func (e *extension) resolveCertDomain(b *ipnlocal.LocalBackend, domain string) (string, error) {
	if domain == "" {
		return "", errors.New("missing domain name")
	}

	// Read the netmap once to get both CertDomains and capabilities atomically.
	nm := b.NetMapNoPeers()
	if nm == nil {
		return "", errors.New("no netmap available")
	}
	certDomains := nm.DNS.CertDomains
	if len(certDomains) == 0 && !e.isBYOFunnelDomain(b, domain) {
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
	if e.isBYOFunnelDomain(b, domain) {
		return domain, nil
	}

	return "", fmt.Errorf("invalid domain %q; must be one of %q", domain, certDomains)
}

// setCertPending sets or clears the in-flight ACME issuance state for
// domain and updates the [certPendingWarnable] to reflect the current
// set of pending domains.
func (e *extension) setCertPending(b *ipnlocal.LocalBackend, domain string, pending bool) {
	e.pendingCertDomainsMu.Lock()
	defer e.pendingCertDomainsMu.Unlock()
	if pending {
		e.pendingCertDomains.Make()
		e.pendingCertDomains.Add(domain)
	} else {
		e.pendingCertDomains.Delete(domain)
	}
	if e.pendingCertDomains.Len() == 0 {
		b.HealthTracker().SetHealthy(certPendingWarnable)
		return
	}
	b.HealthTracker().SetUnhealthy(certPendingWarnable, health.Args{
		health.ArgDomains: joinedPendingCertDomainsLocked(e.pendingCertDomains),
	})
}

func joinedPendingCertDomainsLocked(s set.Set[string]) string {
	ds := slicesx.MapKeys(s)
	slices.Sort(ds)
	return strings.Join(ds, ", ")
}

// parseCertificate returns the leaf certificate from the given
// TLSCertKeyPair's CertPEM.
func parseCertificate(kp *ipnlocal.TLSCertKeyPair) (*x509.Certificate, error) {
	block, _ := pem.Decode(kp.CertPEM)
	if block == nil {
		return nil, fmt.Errorf("error parsing certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, not a CERTIFICATE", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
