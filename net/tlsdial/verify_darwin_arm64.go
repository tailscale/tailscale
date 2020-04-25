// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,arm64,usex509fork

package tlsdial

import (
	"crypto/tls"
	"errors"
	"time"

	"crypto/x509"

	x509fork "tailscale.com/tempfork/x509"
)

func init() {
	platformModifyConf = useX509Fork
}

func useX509Fork(conf *tls.Config) {
	// Modify conf to use our fork of crypto/x509 instead.

	// This prevents crypto/tls from using the standard library's
	// x509. We will then be responsible for the rest.
	conf.InsecureSkipVerify = true

	// Do what crypto/tls would've done for us:
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _verifiedChains [][]*x509.Certificate) error {
		if conf.ServerName == "" {
			return errors.New("no tls.Config.ServerName set")
		}
		if len(rawCerts) == 0 {
			// Shouldn't happen, but.
			return errors.New("no rawCerts from server")
		}
		certs := make([]*x509fork.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509fork.ParseCertificate(asn1Data)
			if err != nil {
				return err
			}
			certs[i] = cert
		}
		opts := x509fork.VerifyOptions{
			CurrentTime:   time.Now(),
			DNSName:       conf.ServerName,
			Intermediates: x509fork.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := certs[0].Verify(opts)
		return err
	}
}
