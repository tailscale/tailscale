// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"regexp"
)

var unsafeHostnameCharacters = regexp.MustCompile(`[^a-zA-Z0-9-\.]`)

type manualCertManager struct {
	cert     *tls.Certificate
	hostname string
}

// NewManualCertManager returns a cert provider which read certificate by given hostname on create.
func NewManualCertManager(certdir, hostname string) (*manualCertManager, error) {
	keyname := unsafeHostnameCharacters.ReplaceAllString(hostname, "")
	crtPath := filepath.Join(certdir, keyname+".crt")
	keyPath := filepath.Join(certdir, keyname+".key")
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("can not load x509 key pair for hostname %q: %w", keyname, err)
	}
	// ensure hostname matches with the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("can not load cert: %w", err)
	}
	if err := x509Cert.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("cert invalid for hostname %q: %w", hostname, err)
	}
	return &manualCertManager{cert: &cert, hostname: hostname}, nil
}

func (m *manualCertManager) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi.ServerName != m.hostname {
		return nil, fmt.Errorf("cert mismatch with hostname: %q", hi.ServerName)
	}
	return m.cert, nil
}
