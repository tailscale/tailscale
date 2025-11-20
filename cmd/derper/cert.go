// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/tailcfg"
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
	cert       *tls.Certificate
	hostname   string // hostname or IP address of server
	noHostname bool   // whether hostname is an IP address
}

// NewManualCertManager returns a cert provider which read certificate by given hostname on create.
func NewManualCertManager(certdir, hostname string) (certProvider, error) {
	keyname := unsafeHostnameCharacters.ReplaceAllString(hostname, "")
	crtPath := filepath.Join(certdir, keyname+".crt")
	keyPath := filepath.Join(certdir, keyname+".key")
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	hostnameIP := net.ParseIP(hostname) // or nil if hostname isn't an IP address
	if err != nil {
		// If the hostname is an IP address, automatically create a
		// self-signed certificate for it.
		var certp *tls.Certificate
		if os.IsNotExist(err) && hostnameIP != nil {
			certp, err = createSelfSignedIPCert(crtPath, keyPath, hostname)
		}
		if err != nil {
			return nil, fmt.Errorf("can not load x509 key pair for hostname %q: %w", keyname, err)
		}
		cert = *certp
	}
	// ensure hostname matches with the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("can not load cert: %w", err)
	}
	if err := x509Cert.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("cert invalid for hostname %q: %w", hostname, err)
	}
	if hostnameIP != nil {
		// If the hostname is an IP address, print out information on how to
		// confgure this in the derpmap.
		dn := &tailcfg.DERPNode{
			Name:     "custom",
			RegionID: 900,
			HostName: hostname,
			CertName: fmt.Sprintf("sha256-raw:%-02x", sha256.Sum256(x509Cert.Raw)),
		}
		dnJSON, _ := json.Marshal(dn)
		log.Printf("Using self-signed certificate for IP address %q. Configure it in DERPMap using: (https://tailscale.com/s/custom-derp)\n  %s", hostname, dnJSON)
	}
	return &manualCertManager{
		cert:       &cert,
		hostname:   hostname,
		noHostname: net.ParseIP(hostname) != nil,
	}, nil
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
	if hi.ServerName != m.hostname && !m.noHostname {
		return nil, fmt.Errorf("cert mismatch with hostname: %q", hi.ServerName)
	}

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

func createSelfSignedIPCert(crtPath, keyPath, ipStr string) (*tls.Certificate, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: ipStr,
		},
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0), // expires in 1 year; a bit over that is rejected by macOS etc

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Set the IP as a SAN.
	template.IPAddresses = []net.IP{ip}

	// Create the self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal EC private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.MkdirAll(filepath.Dir(crtPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for certificate: %v", err)
	}
	if err := os.WriteFile(crtPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to %s: %v", crtPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key to %s: %v", keyPath, err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls.Certificate: %v", err)
	}
	return &tlsCert, nil
}
