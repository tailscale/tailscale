// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tlstest contains code to help test Tailscale's client proxy support.
package tlstest

import (
	"bytes"
	"crypto/ecdsa"
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

// Some baked-in ECDSA keys to speed up tests, not having to burn CPU to
// generate them each time. We only make the certs (which have expiry times)
// at runtime.
//
// They were made with:
//
//	openssl ecparam -name prime256v1 -genkey -noout -out root-ca.key
var (
	//go:embed testdata/root-ca.key
	rootCAKeyPEM []byte

	// TestProxyServerKey is the PEM private key for [TestProxyServerCert].
	//
	//go:embed testdata/proxy.tstest.key
	TestProxyServerKey []byte

	// TestControlPlaneKey is the PEM private key for [TestControlPlaneCert].
	//
	//go:embed testdata/controlplane.tstest.key
	TestControlPlaneKey []byte
)

// TestRootCA returns a self-signed ECDSA root CA certificate (as PEM) for
// testing purposes.
func TestRootCA() []byte {
	return bytes.Clone(testRootCAOncer())
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
	return mustParsePEM(rootCAKeyPEM, x509.ParseECPrivateKey)
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

// KeyPair is a simple struct to hold a certificate and its private key.
type KeyPair struct {
	Domain string
	KeyPEM []byte // PEM-encoded private key
}

// ServerTLSConfig returns a TLS configuration suitable for a server
// using the KeyPair's certificate and private key.
func (p KeyPair) ServerTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair(p.CertPEM(), p.KeyPEM)
	if err != nil {
		panic("invalid TLS key pair: " + err.Error())
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// ProxyServerKeyPair is a KeyPair for a test control plane server
// with domain name "proxy.tstest".
var ProxyServerKeyPair = KeyPair{
	Domain: "proxy.tstest",
	KeyPEM: TestProxyServerKey,
}

// ControlPlaneKeyPair is a KeyPair for a test control plane server
// with domain name "controlplane.tstest".
var ControlPlaneKeyPair = KeyPair{
	Domain: "controlplane.tstest",
	KeyPEM: TestControlPlaneKey,
}

func (p KeyPair) CertPEM() []byte {
	caCert := mustParsePEM(TestRootCA(), x509.ParseCertificate)
	caPriv := mustParsePEM(rootCAKeyPEM, x509.ParseECPrivateKey)
	leafKey := mustParsePEM(p.KeyPEM, x509.ParseECPrivateKey)

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	now := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: p.Domain},
		NotBefore:    now,
		NotAfter:     now.AddDate(2, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{p.Domain},
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
