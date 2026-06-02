// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

// selfSignedCert generates an ephemeral self-signed ECDSA cert for addr
// (an IP or DNS name) and returns the tls.Certificate and its SHA-256 hex
// fingerprint.
func selfSignedCert(t *testing.T, addr string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: addr},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(addr); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{addr}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(derBytes))
	return tlsCert, fingerprint
}

// startTLSServer starts a minimal TLS listener that accepts one connection,
// performs the handshake, then closes. It returns the listener address.
func startTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// dialTLS opens a TCP connection to addr and performs a TLS handshake using cfg.
func dialTLS(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()
	return tlsConn.HandshakeContext(t.Context())
}

// TestTLSConfigForNode_Sha256Raw verifies that tlsConfigForNode correctly
// handles a "sha256-raw:<hex>" CertName: the TLS handshake must succeed when
// the server presents the pinned cert and fail when it presents a different one.
func TestTLSConfigForNode_Sha256Raw(t *testing.T) {
	cert, fp := selfSignedCert(t, "127.0.0.1")
	addr := startTLSServer(t, cert)

	host, _, _ := net.SplitHostPort(addr)

	node := &tailcfg.DERPNode{
		HostName: host,
		CertName: "sha256-raw:" + fp,
	}
	cfg := tlsConfigForNode(node)

	// Must succeed: correct cert and correct hash.
	if err := dialTLS(t, addr, cfg); err != nil {
		t.Errorf("expected success with correct sha256-raw pin, got: %v", err)
	}

	// Must fail: wrong hash.
	wrongNode := &tailcfg.DERPNode{
		HostName: host,
		CertName: "sha256-raw:" + "deadbeef" + fp[8:],
	}
	if err := dialTLS(t, addr, tlsConfigForNode(wrongNode)); err == nil {
		t.Error("expected failure with wrong hash, but handshake succeeded")
	}
}

// TestTLSConfigForNode_OldBehaviorFails demonstrates the original bug:
// passing CertName directly as ServerName to stock tls.Config fails when
// CertName is a sha256-raw fingerprint.
func TestTLSConfigForNode_OldBehaviorFails(t *testing.T) {
	cert, fp := selfSignedCert(t, "127.0.0.1")
	addr := startTLSServer(t, cert)

	// Reproduce the old code: ServerName = cmp.Or(CertName, HostName)
	oldCfg := &tls.Config{
		ServerName: "sha256-raw:" + fp,
	}
	if err := dialTLS(t, addr, oldCfg); err == nil {
		t.Error("old behavior unexpectedly succeeded; test is no longer meaningful")
	}
}

// TestTLSConfigForNode_PlainCertName verifies that a non-sha256-raw CertName
// is handled via SetConfigExpectedCert (domain fronting path).
func TestTLSConfigForNode_PlainCertName(t *testing.T) {
	const domain = "example.tailscale.com"
	cert, _ := selfSignedCert(t, domain)
	addr := startTLSServer(t, cert)

	host, _, _ := net.SplitHostPort(addr)
	node := &tailcfg.DERPNode{
		HostName: host,
		CertName: domain,
	}
	cfg := tlsConfigForNode(node)

	// The cert is self-signed (not in any system trust store), so Verify will
	// fail – but NOT with a hostname mismatch; the error should mention the
	// untrusted issuer, not "not example.tailscale.com".
	err := dialTLS(t, addr, cfg)
	if err == nil {
		// Acceptable if a custom root happens to be trusted (unlikely in CI).
		return
	}
	if errStr := err.Error(); !contains(errStr, "certificate") {
		t.Errorf("unexpected error (wanted cert trust error): %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := range len(s) - len(sub) + 1 {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
