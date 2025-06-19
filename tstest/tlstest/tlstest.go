// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tlstest contains code to help test Tailscale's TLS support without
// depending on real WebPKI roots or certificates during tests.
package tlstest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// TestRootCA returns a self-signed ECDSA root CA certificate (as PEM) for
// testing purposes.
//
// Typical use in a test is like:
//
//	bakedroots.ResetForTest(t, tlstest.TestRootCA())
func TestRootCA() []byte {
	return bytes.Clone(testRootCAOncer())
}

// cache for [privateKey], so it always returns the same key for a given domain.
var (
	mu          sync.Mutex
	privateKeys = make(map[string][]byte) // domain -> private key PEM
)

// caDomain is a fake domain name to repreesnt the private key for the root CA.
const caDomain = "_root"

// privateKey returns a PEM-encoded test ECDSA private key for the given domain.
func privateKey(domain string) (pemBytes []byte) {
	mu.Lock()
	defer mu.Unlock()
	if pemBytes, ok := privateKeys[domain]; ok {
		return bytes.Clone(pemBytes)
	}
	defer func() { privateKeys[domain] = bytes.Clone(pemBytes) }()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ECDSA key for %q: %v", domain, err))
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal ECDSA key for %q: %v", domain, err))
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		panic(fmt.Sprintf("failed to encode PEM: %v", err))
	}
	return buf.Bytes()
}

var testRootCAOncer = sync.OnceValue(func() []byte {
	key := rootCAKey()
	now := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Tailscale Unit Test ECDSA Root",
			Organization: []string{"Tailscale Test Org"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(5, 0, 0),

		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          mustSKID(&key.PublicKey),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return pemCert(der)
})

func pemCert(der []byte) []byte {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		panic(fmt.Sprintf("failed to encode PEM: %v", err))
	}
	return buf.Bytes()
}

var rootCAKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	return mustParsePEM(privateKey(caDomain), x509.ParseECPrivateKey)
})

func mustParsePEM[T any](pemBytes []byte, parse func([]byte) (T, error)) T {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) > 0 {
		panic("invalid PEM")
	}
	v, err := parse(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("invalid PEM: %v", err))
	}
	return v
}

// Domain is a fake domain name used in TLS tests.
//
// They don't have real DNS records. Tests are expected to fake DNS
// lookups and dials for these domains.
type Domain string

// ProxyServer is a domain name for a hypothetical proxy server.
const (
	ProxyServer = Domain("proxy.tstest")

	// ControlPlane is a domain name for a test control plane server.
	ControlPlane = Domain("controlplane.tstest")

	// Derper is a domain name for a test DERP server.
	Derper = Domain("derp.tstest")
)

// ServerTLSConfig returns a TLS configuration suitable for a server
// using the KeyPair's certificate and private key.
func (d Domain) ServerTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair(d.CertPEM(), privateKey(string(d)))
	if err != nil {
		panic("invalid TLS key pair: " + err.Error())
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// KeyPEM returns a PEM-encoded private key for the domain.
func (d Domain) KeyPEM() []byte {
	return privateKey(string(d))
}

// CertPEM returns a PEM-encoded certificate for the domain.
func (d Domain) CertPEM() []byte {
	caCert := mustParsePEM(TestRootCA(), x509.ParseCertificate)
	caPriv := mustParsePEM(privateKey(caDomain), x509.ParseECPrivateKey)
	leafKey := mustParsePEM(d.KeyPEM(), x509.ParseECPrivateKey)

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	now := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: string(d)},
		NotBefore:    now,
		NotAfter:     now.AddDate(2, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{string(d)},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &leafKey.PublicKey, caPriv)
	if err != nil {
		panic(err)
	}
	return pemCert(der)
}

func mustSKID(pub *ecdsa.PublicKey) []byte {
	skid, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return skid[:20] // same as x509 library
}
