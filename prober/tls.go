// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
	"tailscale.com/util/multierr"
)

const expiresSoon = 7 * 24 * time.Hour // 7 days from now

// TLS returns a Probe that healthchecks a TLS endpoint.
//
// The ProbeFunc connects to a hostname (host:port string), does a TLS
// handshake, verifies that the hostname matches the presented certificate,
// checks certificate validity time and OCSP revocation status.
func TLS(hostname string) ProbeFunc {
	return func(ctx context.Context) error {
		return probeTLS(ctx, hostname)
	}
}

func probeTLS(ctx context.Context, hostname string) error {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		return err
	}

	dialer := &tls.Dialer{Config: &tls.Config{ServerName: host}}
	conn, err := dialer.DialContext(ctx, "tcp", hostname)
	if err != nil {
		return fmt.Errorf("connecting to %q: %w", hostname, err)
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

	if len(leafCert.OCSPServer) == 0 {
		errs = append(errs, fmt.Errorf("no OCSP server presented in leaf cert for %v", leafCert.Subject))
		return
	}

	ocspResp, err := getOCSPResponse(ctx, leafCert.OCSPServer[0], leafCert, issuerCert)
	if err != nil {
		errs = append(errs, errors.Wrapf(err, "OCSP verification failed for %v", leafCert.Subject))
		return
	}

	if ocspResp.Status == ocsp.Unknown {
		errs = append(errs, fmt.Errorf("unknown OCSP verification status for %v", leafCert.Subject))
	}

	if ocspResp.Status == ocsp.Revoked {
		errs = append(errs, fmt.Errorf("cert for %v has been revoked on %v, reason: %v", leafCert.Subject, ocspResp.RevokedAt, ocspResp.RevocationReason))
	}
	return
}

func getOCSPResponse(ctx context.Context, ocspServer string, leafCert, issuerCert *x509.Certificate) (*ocsp.Response, error) {
	reqb, err := ocsp.CreateRequest(leafCert, issuerCert, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create OCSP request")
	}
	hreq, err := http.NewRequestWithContext(ctx, "POST", ocspServer, bytes.NewReader(reqb))
	if err != nil {
		return nil, errors.Wrap(err, "could not create OCSP POST request")
	}
	hreq.Header.Add("Content-Type", "application/ocsp-request")
	hreq.Header.Add("Accept", "application/ocsp-response")
	hresp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return nil, errors.Wrap(err, "OCSP request failed")
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp: non-200 status code from OCSP server: %s", hresp.Status)
	}
	lr := io.LimitReader(hresp.Body, 10<<20) // 10MB
	ocspB, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	return ocsp.ParseResponse(ocspB, issuerCert)
}
