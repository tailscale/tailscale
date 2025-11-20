// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tlsdial generates tls.Config values and does x509 validation of
// certs. It bakes in the LetsEncrypt roots so even if the user's machine
// doesn't have TLS roots, we can at least connect to Tailscale's LetsEncrypt
// services.  It's the unified point where we can add shared policy on outgoing
// TLS connections from the three places in the client that connect to Tailscale
// (logs, control, DERP).
package tlsdial

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/derp/derpconst"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/net/bakedroots"
	"tailscale.com/net/tlsdial/blockblame"
)

var counterFallbackOK int32 // atomic

var debug = envknob.RegisterBool("TS_DEBUG_TLS_DIAL")

// tlsdialWarningPrinted tracks whether we've printed a warning about a given
// hostname already, to avoid log spam for users with custom DERP servers,
// Headscale, etc.
var tlsdialWarningPrinted sync.Map // map[string]bool

var mitmBlockWarnable = health.Register(&health.Warnable{
	Code:  "blockblame-mitm-detected",
	Title: "Network may be blocking Tailscale",
	Text: func(args health.Args) string {
		return fmt.Sprintf("Network equipment from %q may be blocking Tailscale traffic on this network. Connect to another network, or contact your network administrator for assistance.", args["manufacturer"])
	},
	Severity:            health.SeverityMedium,
	ImpactsConnectivity: true,
})

// Config returns a tls.Config for connecting to a server that
// uses system roots for validation but, if those fail, also tries
// the baked-in LetsEncrypt roots as a fallback validation method.
//
// If base is non-nil, it's cloned as the base config before
// being configured and returned.
// If ht is non-nil, it's used to report health errors.
func Config(ht *health.Tracker, base *tls.Config) *tls.Config {
	var conf *tls.Config
	if base == nil {
		conf = new(tls.Config)
	} else {
		conf = base.Clone()
	}

	// Note: we do NOT set conf.ServerName here (as we accidentally did
	// previously), as this path is also used when dialing an HTTPS proxy server
	// (through which we'll send a CONNECT request to get a TCP connection to do
	// the real TCP connection) because host is the ultimate hostname, but this
	// tls.Config is used for both the proxy and the ultimate target.

	if buildfeatures.HasDebug {
		// If SSLKEYLOGFILE is set, it's a file to which we write our TLS private keys
		// in a way that WireShark can read.
		//
		// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
		if n := os.Getenv("SSLKEYLOGFILE"); n != "" {
			f, err := os.OpenFile(n, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("WARNING: writing to SSLKEYLOGFILE %v", n)
			conf.KeyLogWriter = f
		}
	}

	if conf.InsecureSkipVerify {
		panic("unexpected base.InsecureSkipVerify")
	}
	if conf.VerifyConnection != nil {
		panic("unexpected base.VerifyConnection")
	}

	// Set InsecureSkipVerify to prevent crypto/tls from doing its
	// own cert verification, as do the same work that it'd do
	// (with the baked-in fallback root) in the VerifyConnection hook.
	conf.InsecureSkipVerify = true
	conf.VerifyConnection = func(cs tls.ConnectionState) (retErr error) {
		dialedHost := cs.ServerName

		if dialedHost == "log.tailscale.com" && hostinfo.IsNATLabGuestVM() {
			// Allow log.tailscale.com TLS MITM for integration tests when
			// the client's running within a NATLab VM.
			return nil
		}

		// Perform some health checks on this certificate before we do
		// any verification.
		var cert *x509.Certificate
		var selfSignedIssuer string
		if certs := cs.PeerCertificates; len(certs) > 0 {
			cert = certs[0]
			if certIsSelfSigned(cert) {
				selfSignedIssuer = cert.Issuer.String()
			}
		}
		if ht != nil {
			defer func() {
				if retErr != nil && cert != nil {
					// Is it a MITM SSL certificate from a well-known network appliance manufacturer?
					// Show a dedicated warning.
					m, ok := blockblame.VerifyCertificate(cert)
					if ok {
						log.Printf("tlsdial: server cert seen while dialing %q looks like %q equipment (could be blocking Tailscale)", dialedHost, m.Name)
						ht.SetUnhealthy(mitmBlockWarnable, health.Args{"manufacturer": m.Name})
					} else {
						ht.SetHealthy(mitmBlockWarnable)
					}
				} else {
					ht.SetHealthy(mitmBlockWarnable)
				}
				if retErr != nil && selfSignedIssuer != "" {
					// Self-signed certs are never valid.
					//
					// TODO(bradfitz): plumb down the selfSignedIssuer as a
					// structured health warning argument.
					ht.SetTLSConnectionError(cs.ServerName, fmt.Errorf("likely intercepted connection; certificate is self-signed by %v", selfSignedIssuer))
				} else {
					// Ensure we clear any error state for this ServerName.
					ht.SetTLSConnectionError(cs.ServerName, nil)
					if selfSignedIssuer != "" {
						// Log the self-signed issuer, but don't treat it as an error.
						log.Printf("tlsdial: warning: server cert for %q passed x509 validation but is self-signed by %q", dialedHost, selfSignedIssuer)
					}
				}
			}()
		}

		// First try doing x509 verification with the system's
		// root CA pool.
		opts := x509.VerifyOptions{
			DNSName:       dialedHost,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, errSys := cs.PeerCertificates[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(sys %q): %v", dialedHost, errSys)
		}
		if !buildfeatures.HasBakedRoots || (errSys == nil && !debug()) {
			return errSys
		}

		// If we have baked-in LetsEncrypt roots and we either failed above, or
		// debug logging is enabled, also verify with LetsEncrypt.
		opts.Roots = bakedroots.Get()
		_, bakedErr := cs.PeerCertificates[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(bake %q): %v", dialedHost, bakedErr)
		} else if bakedErr != nil {
			if _, loaded := tlsdialWarningPrinted.LoadOrStore(dialedHost, true); !loaded {
				if errSys != nil {
					log.Printf("tlsdial: error: server cert for %q failed both system roots & Let's Encrypt root validation", dialedHost)
				}
			}
		}

		if errSys == nil {
			return nil
		} else if bakedErr == nil {
			atomic.AddInt32(&counterFallbackOK, 1)
			return nil
		}
		return errSys
	}
	return conf
}

func certIsSelfSigned(cert *x509.Certificate) bool {
	// A certificate is determined to be self-signed if the certificate's
	// subject is the same as its issuer.
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

// SetConfigExpectedCert modifies c to expect and verify that the server returns
// a certificate for the provided certDNSName.
//
// This is for user-configurable client-side domain fronting support,
// where we send one SNI value but validate a different cert.
func SetConfigExpectedCert(c *tls.Config, certDNSName string) {
	if c.ServerName == certDNSName {
		return
	}
	if c.ServerName == "" {
		c.ServerName = certDNSName
		return
	}
	// Set InsecureSkipVerify to prevent crypto/tls from doing its
	// own cert verification, but do the same work that it'd do
	// (but using certDNSName) in the VerifyPeerCertificate hook.
	c.InsecureSkipVerify = true
	c.VerifyConnection = nil
	c.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certs presented")
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return err
			}
			certs[i] = cert
		}
		opts := x509.VerifyOptions{
			CurrentTime:   time.Now(),
			DNSName:       certDNSName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, errSys := certs[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(sys %q/%q): %v", c.ServerName, certDNSName, errSys)
		}
		if !buildfeatures.HasBakedRoots || errSys == nil {
			return errSys
		}
		opts.Roots = bakedroots.Get()
		_, err := certs[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(bake %q/%q): %v", c.ServerName, certDNSName, err)
		}
		if err == nil {
			return nil
		}
		return errSys
	}
}

// SetConfigExpectedCertHash configures c's VerifyPeerCertificate function to
// require that exactly 1 cert is presented (not counting any present MetaCert),
// and that the hex of its SHA256 hash is equal to wantFullCertSHA256Hex and
// that it's a valid cert for c.ServerName.
func SetConfigExpectedCertHash(c *tls.Config, wantFullCertSHA256Hex string) {
	if c.VerifyPeerCertificate != nil {
		panic("refusing to override tls.Config.VerifyPeerCertificate")
	}

	// Set InsecureSkipVerify to prevent crypto/tls from doing its
	// own cert verification, but do the same work that it'd do
	// (but using certDNSName) in the VerifyConnection hook.
	c.InsecureSkipVerify = true

	c.VerifyConnection = func(cs tls.ConnectionState) error {
		dialedHost := cs.ServerName
		var sawGoodCert bool

		for _, cert := range cs.PeerCertificates {
			if strings.HasPrefix(cert.Subject.CommonName, derpconst.MetaCertCommonNamePrefix) {
				continue
			}
			if sawGoodCert {
				return errors.New("unexpected multiple certs presented")
			}
			if fmt.Sprintf("%02x", sha256.Sum256(cert.Raw)) != wantFullCertSHA256Hex {
				return fmt.Errorf("cert hash does not match expected cert hash")
			}
			if dialedHost != "" { // it's empty when dialing a derper by IP with no hostname
				if err := cert.VerifyHostname(dialedHost); err != nil {
					return fmt.Errorf("cert does not match server name %q: %w", dialedHost, err)
				}
			}
			now := time.Now()
			if now.After(cert.NotAfter) {
				return fmt.Errorf("cert expired %v", cert.NotAfter)
			}
			if now.Before(cert.NotBefore) {
				return fmt.Errorf("cert not yet valid until %v; is your clock correct?", cert.NotBefore)
			}
			sawGoodCert = true
		}
		if !sawGoodCert {
			return errors.New("expected cert not presented")
		}
		return nil
	}
}

// NewTransport returns a new HTTP transport that verifies TLS certs using this
// package, including its baked-in LetsEncrypt fallback roots.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d tls.Dialer
			d.Config = Config(nil, nil)
			return d.DialContext(ctx, network, addr)
		},
	}
}
