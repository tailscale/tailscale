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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
)

var counterFallbackOK int32 // atomic

// If SSLKEYLOGFILE is set, it's a file to which we write our TLS private keys
// in a way that WireShark can read.
//
// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
var sslKeyLogFile = os.Getenv("SSLKEYLOGFILE")

var debug = envknob.RegisterBool("TS_DEBUG_TLS_DIAL")

// tlsdialWarningPrinted tracks whether we've printed a warning about a given
// hostname already, to avoid log spam for users with custom DERP servers,
// Headscale, etc.
var tlsdialWarningPrinted sync.Map // map[string]bool

// Config returns a tls.Config for connecting to a server.
// If base is non-nil, it's cloned as the base config before
// being configured and returned.
// If ht is non-nil, it's used to report health errors.
func Config(host string, ht *health.Tracker, base *tls.Config) *tls.Config {
	var conf *tls.Config
	if base == nil {
		conf = new(tls.Config)
	} else {
		conf = base.Clone()
	}
	conf.ServerName = host

	if n := sslKeyLogFile; n != "" {
		f, err := os.OpenFile(n, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("WARNING: writing to SSLKEYLOGFILE %v", n)
		conf.KeyLogWriter = f
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
		if host == "log.tailscale.io" && hostinfo.IsNATLabGuestVM() {
			// Allow log.tailscale.io TLS MITM for integration tests when
			// the client's running within a NATLab VM.
			return nil
		}

		// Perform some health checks on this certificate before we do
		// any verification.
		var selfSignedIssuer string
		if certs := cs.PeerCertificates; len(certs) > 0 && certIsSelfSigned(certs[0]) {
			selfSignedIssuer = certs[0].Issuer.String()
		}
		if ht != nil {
			defer func() {
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
						log.Printf("tlsdial: warning: server cert for %q passed x509 validation but is self-signed by %q", host, selfSignedIssuer)
					}
				}
			}()
		}

		// First try doing x509 verification with the system's
		// root CA pool.
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, errSys := cs.PeerCertificates[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(sys %q): %v", host, errSys)
		}

		// Always verify with our baked-in Let's Encrypt certificate,
		// so we can log an informational message. This is useful for
		// detecting SSL MiTM.
		opts.Roots = bakedInRoots()
		_, bakedErr := cs.PeerCertificates[0].Verify(opts)
		if debug() {
			log.Printf("tlsdial(bake %q): %v", host, bakedErr)
		} else if bakedErr != nil {
			if _, loaded := tlsdialWarningPrinted.LoadOrStore(host, true); !loaded {
				if errSys == nil {
					log.Printf("tlsdial: warning: server cert for %q is not a Let's Encrypt cert", host)
				} else {
					log.Printf("tlsdial: error: server cert for %q failed to verify and is not a Let's Encrypt cert", host)
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
	if c.VerifyPeerCertificate != nil {
		panic("refusing to override tls.Config.VerifyPeerCertificate")
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
		if errSys == nil {
			return nil
		}
		opts.Roots = bakedInRoots()
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

// NewTransport returns a new HTTP transport that verifies TLS certs using this
// package, including its baked-in LetsEncrypt fallback roots.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var d tls.Dialer
			d.Config = Config(host, nil, nil)
			return d.DialContext(ctx, network, addr)
		},
	}
}

/*
letsEncryptX1 is the LetsEncrypt X1 root:

Certificate:

	Data:
	    Version: 3 (0x2)
	    Serial Number:
	        82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
	    Signature Algorithm: sha256WithRSAEncryption
	    Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	    Validity
	        Not Before: Jun  4 11:04:38 2015 GMT
	        Not After : Jun  4 11:04:38 2035 GMT
	    Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	    Subject Public Key Info:
	        Public Key Algorithm: rsaEncryption
	            RSA Public-Key: (4096 bit)

We bake it into the binary as a fallback verification root,
in case the system we're running on doesn't have it.
(Tailscale runs on some ancient devices.)

To test that this code is working on Debian/Ubuntu:

$ sudo mv /usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt{,.old}
$ sudo update-ca-certificates

Then restart tailscaled. To also test dnsfallback's use of it, nuke
your /etc/resolv.conf and it should still start & run fine.
*/
const letsEncryptX1 = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
`

var bakedInRootsOnce struct {
	sync.Once
	p *x509.CertPool
}

func bakedInRoots() *x509.CertPool {
	bakedInRootsOnce.Do(func() {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM([]byte(letsEncryptX1)) {
			panic("bogus PEM")
		}
		bakedInRootsOnce.p = p
	})
	return bakedInRootsOnce.p
}
