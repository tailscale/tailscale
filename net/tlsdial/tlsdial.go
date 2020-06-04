// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tlsdial originally existed to set up a tls.Config for x509
// validation, using a memory-optimized path for iOS, but then we
// moved that to the tailscale/go tree instead, so now this package
// does very little. But for now we keep it as a unified point where
// we might want to add shared policy on outgoing TLS connections from
// the 3 places in the client that connect to Tailscale (logs,
// control, DERP).
package tlsdial

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

// Config returns a tls.Config for connecting to a server.
// If base is non-nil, it's cloned as the base config before
// being configured and returned.
func Config(host string, base *tls.Config) *tls.Config {
	var conf *tls.Config
	if base == nil {
		conf = new(tls.Config)
	} else {
		conf = base.Clone()
	}
	conf.ServerName = host

	return conf
}

// SetConfigExpectedCert modifies c to expect and verify that the server returns
// a certificate for the provided certDNSName.
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
		_, err := certs[0].Verify(opts)
		return err
	}
}
