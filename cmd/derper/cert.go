// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	//
	// The returned Config must have a GetCertificate function set and that
	// function must return a unique *tls.Certificate for each call. The
	// returned *tls.Certificate will be mutated by the caller to append to the
	// (*tls.Certificate).Certificate field.
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
	if err := x509Cert.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("cert invalid for hostname %q: %w", hostname, err)
	}
	return &manualCertManager{cert: &cert, hostname: hostname}, nil
}

func (m *manualCertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: nil,
		NextProtos: []string{
			"http/1.1",
		},
		GetCertificate: m.getCertificate,
	}
}

func (m *manualCertManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// if hi.ServerName != m.hostname {
	// 	return nil, fmt.Errorf("cert mismatch with hostname: %q", hi.ServerName)
	// }

	// Return a shallow copy of the cert so the caller can append to its
	// Certificate field.
	certCopy := new(tls.Certificate)
	*certCopy = *m.cert
	certCopy.Certificate = certCopy.Certificate[:len(certCopy.Certificate):len(certCopy.Certificate)]
	return certCopy, nil
}

func (m *manualCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}
