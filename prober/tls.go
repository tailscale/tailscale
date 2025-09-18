// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/util/multierr"
)

const expiresSoon = 7 * 24 * time.Hour // 7 days from now
// Let’s Encrypt promises to issue certificates with CRL servers after 2025-05-07:
// https://letsencrypt.org/2024/12/05/ending-ocsp/
// https://github.com/tailscale/tailscale/issues/15912
const letsEncryptStartedStaplingCRL int64 = 1746576000 // 2025-05-07 00:00:00 UTC

// TLS returns a Probe that healthchecks a TLS endpoint.
//
// The ProbeFunc connects to a hostPort (host:port string), does a TLS
// handshake, verifies that the hostname matches the presented certificate,
// checks certificate validity time and OCSP revocation status.
//
// The TLS config is optional and may be nil.
func TLS(hostPort string, config *tls.Config) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeTLS(ctx, config, hostPort)
		},
		Class: "tls",
	}
}

// TLSWithIP is like TLS, but dials the provided dialAddr instead of using DNS
// resolution. Use config.ServerName to send SNI and validate the name in the
// cert.
func TLSWithIP(dialAddr netip.AddrPort, config *tls.Config) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeTLS(ctx, config, dialAddr.String())
		},
		Class: "tls",
	}
}

func probeTLS(ctx context.Context, config *tls.Config, dialHostPort string) error {
	dialer := &tls.Dialer{Config: config}
	conn, err := dialer.DialContext(ctx, "tcp", dialHostPort)
	if err != nil {
		return fmt.Errorf("connecting to %q: %w", dialHostPort, err)
	}
	defer conn.Close()

	tlsConnState := conn.(*tls.Conn).ConnectionState()
	return validateConnState(ctx, &tlsConnState)
}

// validateConnState verifies certificate validity time in all certificates
// returned by the TLS server and checks OCSP revocation status for the
// leaf cert.
func validateConnState(ctx context.Context, cs *tls.ConnectionState) (returnerr error) {
	var errs []error
	defer func() {
		returnerr = multierr.New(errs...)
	}()
	latestAllowedExpiration := time.Now().Add(expiresSoon)

	var leafCert *x509.Certificate
	var issuerCert *x509.Certificate
	var leafAuthorityKeyID string
	// PeerCertificates will never be len == 0 on the client side
	for i, cert := range cs.PeerCertificates {
		if i == 0 {
			leafCert = cert
			leafAuthorityKeyID = string(cert.AuthorityKeyId)
		}
		if i > 0 {
			if leafAuthorityKeyID == string(cert.SubjectKeyId) {
				issuerCert = cert
			}
		}

		// Do not check certificate validity period for self-signed certs.
		// The practical reason is to avoid raising alerts for expiring
		// DERP metaCert certificates that are returned as part of regular
		// TLS handshake.
		if string(cert.SubjectKeyId) == string(cert.AuthorityKeyId) {
			continue
		}

		if time.Now().Before(cert.NotBefore) {
			errs = append(errs, fmt.Errorf("one of the certs has NotBefore in the future (%v): %v", cert.NotBefore, cert.Subject))
		}
		if latestAllowedExpiration.After(cert.NotAfter) {
			left := cert.NotAfter.Sub(time.Now())
			errs = append(errs, fmt.Errorf("one of the certs expires in %v: %v", left, cert.Subject))
		}
	}

	if len(leafCert.CRLDistributionPoints) == 0 {
		if !slices.Contains(leafCert.Issuer.Organization, "Let's Encrypt") {
			// LE certs contain a CRL, but certs from other CAs might not.
			return
		}
		if leafCert.NotBefore.Before(time.Unix(letsEncryptStartedStaplingCRL, 0)) {
			// Certificate might not have a CRL.
			return
		}
		errs = append(errs, fmt.Errorf("no CRL server presented in leaf cert for %v", leafCert.Subject))
		return
	}

	err := checkCertCRL(ctx, leafCert.CRLDistributionPoints[0], leafCert, issuerCert)
	if err != nil {
		errs = append(errs, fmt.Errorf("CRL verification failed for %v: %w", leafCert.Subject, err))
	}
	return
}

func checkCertCRL(ctx context.Context, crlURL string, leafCert, issuerCert *x509.Certificate) error {
	hreq, err := http.NewRequestWithContext(ctx, "GET", crlURL, nil)
	if err != nil {
		return fmt.Errorf("could not create CRL GET request: %w", err)
	}
	hresp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return fmt.Errorf("CRL request failed: %w", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return fmt.Errorf("crl: non-200 status code from CRL server: %s", hresp.Status)
	}
	lr := io.LimitReader(hresp.Body, 10<<20) // 10MB
	crlB, err := io.ReadAll(lr)
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(crlB)
	if err != nil {
		return fmt.Errorf("could not parse CRL: %w", err)
	}

	if err := crl.CheckSignatureFrom(issuerCert); err != nil {
		return fmt.Errorf("could not verify CRL signature: %w", err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(leafCert.SerialNumber) == 0 {
			return fmt.Errorf("cert for %v has been revoked on %v, reason: %v", leafCert.Subject, revoked.RevocationTime, revoked.ReasonCode)
		}
	}

	return nil
}
