// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"net/netip"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
	"tailscale.com/util/multierr"
)

const expiresSoon = 7 * 24 * time.Hour // 7 days from now

// TLS returns a Probe that healthchecks a TLS endpoint.
//
// The ProbeFunc connects to a hostPort (host:port string), does a TLS
// handshake, verifies that the hostname matches the presented certificate,
// checks certificate validity time and OCSP revocation status.
func TLS(hostPort string) ProbeFunc {
	return func(ctx context.Context) error {
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			return err
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return fmt.Errorf("parsing port %q: %w", portStr, err)
		}

		var resolver net.Resolver
		addrs, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("resolving IP for %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("no addrs for %q", host)
		}

		return probeTLS(ctx, TLSOpts{
			CertDomain: host,

			// TODO(andrew-d): do something smarter than always
			// checking the first IP.
			DialAddr: netip.AddrPortFrom(addrs[0], uint16(port)),
		})
	}
}

// TLSWithIP is like TLS, but dials the provided dialAddr instead
// of using DNS resolution. The certDomain is the expected name in
// the cert (and the SNI name to send).
func TLSWithIP(certDomain string, dialAddr netip.AddrPort) ProbeFunc {
	return func(ctx context.Context) error {
		return probeTLS(ctx, TLSOpts{
			CertDomain: certDomain,
			DialAddr:   dialAddr,
		})
	}
}

// TLSOpts is the set of options for TLSWithOpts.
type TLSOpts struct {
	// CertDomain is the expected name in the cert (and the SNI name to
	// send) when connecting to the server.
	CertDomain string

	// DialAddr is the IP address to dial. It must be provided.
	DialAddr netip.AddrPort

	// Network is the network to use when dialing. It must be one of "tcp",
	// "tcp4", or "tcp6". If not provided, "tcp" is used.
	Network string

	// MinExpiry is the minimum time before a certificate expires that is
	// considered healthy. If not provided, a default value will be used.
	MinExpiry time.Duration
}

// TLSWithOpts returns a Probe that healthchecks a TLS endpoint.
//
// This is the fully-customizable version of TLS; the TLS and TLSWithIP
// functions wrap this.
func TLSWithOpts(opts TLSOpts) ProbeFunc {
	if opts.Network == "" {
		opts.Network = "tcp"
	}

	return func(ctx context.Context) error {
		return probeTLS(ctx, opts)
	}
}

func probeTLS(ctx context.Context, opts TLSOpts) error {
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: opts.CertDomain}}
	conn, err := dialer.DialContext(ctx, opts.Network, opts.DialAddr.String())
	if err != nil {
		return fmt.Errorf("connecting to %q: %w", opts.DialAddr.String(), err)
	}
	defer conn.Close()

	tlsConnState := conn.(*tls.Conn).ConnectionState()
	return validateConnState(ctx, &tlsConnState, &opts)
}

// validateConnState verifies certificate validity time in all certificates
// returned by the TLS server and checks OCSP revocation status for the
// leaf cert.
func validateConnState(ctx context.Context, cs *tls.ConnectionState, opts *TLSOpts) (returnerr error) {
	var errs []error
	defer func() {
		returnerr = multierr.New(errs...)
	}()

	var latestAllowedExpiration time.Time
	if opts.MinExpiry > 0 {
		latestAllowedExpiration = time.Now().Add(opts.MinExpiry)
	} else {
		latestAllowedExpiration = time.Now().Add(expiresSoon)
	}

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
