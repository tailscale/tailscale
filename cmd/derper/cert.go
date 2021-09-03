// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
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

func certProviderByCertMode(mode, dir string) (certProvider, error) {
	if dir == "" {
		return nil, errors.New("missing required --certdir flag")
	}
	switch mode {
	case "letsencrypt":
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*hostname),
			Cache:      autocert.DirCache(dir),
		}
		if *hostname == "derp.tailscale.com" {
			certManager.HostPolicy = prodAutocertHostPolicy
			certManager.Email = "security@tailscale.com"
		}
		return certManager, nil
	case "manual":
		return &manualCertManager{
			certdir: dir,
		}, nil
	default:
		return nil, fmt.Errorf("unsupport cert mode: %q", mode)
	}
}

type manualCertManager struct {
	certdir string
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
	// If server name is provided (which means SNI), search for the file.
	// Or, use local IP as cert name.
	keyname := hi.ServerName
	if keyname == "" {
		keyname = hi.Conn.LocalAddr().String()
	}
	// RFC basically only allow [0-9a-zA-Z\.-] in SNI, so
	// We will follow it for security purpose.
	// Also, unnecessary to check concated string.
	keyname = unsafeHostnameCharacters.ReplaceAllString(keyname, "")
	crtPath := filepath.Join(m.certdir, keyname+".crt")
	keyPath := filepath.Join(m.certdir, keyname+".key")
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("can not load x509 key pair for hostname %q: %w", keyname, err)
	}
	return &cert, err
}

func (m *manualCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}
