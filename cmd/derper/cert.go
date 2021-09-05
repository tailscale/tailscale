// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"

	"golang.org/x/crypto/acme/autocert"
)

var unsafeHostnameCharacters = regexp.MustCompile(`[^a-zA-Z0-9-\.]`)

type certProvider interface {
	// TLSConfig creates a new TLS config suitable for net/http.Server servers.
	TLSConfig() *tls.Config
	// HTTPHandler handle ACME related request, if any.
	HTTPHandler(fallback http.Handler) http.Handler
}

func certProviderByCertMode(mode, dir, hostname string) (certProvider, error) {
	if dir == "" {
		return nil, errors.New("missing required --certdir flag")
	}
	switch mode {
	case "letsencrypt":
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache(dir),
		}
		if hostname == "derp.tailscale.com" {
			certManager.HostPolicy = prodAutocertHostPolicy
			certManager.Email = "security@tailscale.com"
		}
		return certManager, nil
	case "manual":
		return NewManualCertManager(dir, hostname)
	default:
		return nil, fmt.Errorf("unsupport cert mode: %q", mode)
	}
}

type manualCertManager struct {
	cert     *tls.Certificate
	hostname string
}

// NewManualCertManager returns a cert provider which read certificate by given hostname on create.
func NewManualCertManager(certdir, hostname string) (certProvider, error) {
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
	if x509Cert.VerifyHostname(hostname) != nil {
		return nil, errors.New("refuse to load cert: hostname mismatch with key")
	}
	return &manualCertManager{cert: &cert, hostname: hostname}, nil
}

func (m *manualCertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: nil,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
		GetCertificate: m.getCertificate,
	}
}

func (m *manualCertManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi.ServerName != m.hostname {
		return nil, fmt.Errorf("cert mismatch with hostname: %q", hi.ServerName)
	}
	return m.cert, nil
}

func (m *manualCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}
