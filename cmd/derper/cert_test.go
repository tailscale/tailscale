// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
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
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Verify that in --certmode=manual mode, we can use a bare IP address
// as the --hostname and that GetCertificate will return it.
func TestCertIP(t *testing.T) {
	dir := t.TempDir()
	const hostname = "1.2.3.4"

	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		t.Fatalf("invalid IP address %q", hostname)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Tailscale Test Corp"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certOut, err := os.Create(filepath.Join(dir, hostname+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("Error closing cert.pem: %v", err)
	}

	keyOut, err := os.OpenFile(filepath.Join(dir, hostname+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("Error closing key.pem: %v", err)
	}

	cp, err := certProviderByCertMode("manual", dir, hostname)
	if err != nil {
		t.Fatal(err)
	}
	back, err := cp.TLSConfig().GetCertificate(&tls.ClientHelloInfo{
		ServerName: "", // no SNI
	})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if back == nil {
		t.Fatalf("GetCertificate returned nil")
	}
}

// Test that we can dial a raw IP without using a hostname and without a WebPKI
// cert, validating the cert against the signature of the cert in the DERP map's
// DERPNode.
//
// See https://github.com/tailscale/tailscale/issues/11776.
func TestPinnedCertRawIP(t *testing.T) {
	td := t.TempDir()
	cp, err := NewManualCertManager(td, "127.0.0.1")
	if err != nil {
		t.Fatalf("NewManualCertManager: %v", err)
	}

	cert, err := cp.TLSConfig().GetCertificate(&tls.ClientHelloInfo{
		ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ds := derpserver.New(key.NewNode(), t.Logf)

	derpHandler := derpserver.Handler(ds)
	mux := http.NewServeMux()
	mux.Handle("/derp", derpHandler)

	var hs http.Server
	hs.Handler = mux
	hs.TLSConfig = cp.TLSConfig()
	ds.ModifyTLSConfigToAddMetaCert(hs.TLSConfig)
	go hs.ServeTLS(ln, "", "")

	lnPort := ln.Addr().(*net.TCPAddr).Port

	reg := &tailcfg.DERPRegion{
		RegionID: 900,
		Nodes: []*tailcfg.DERPNode{
			{
				RegionID: 900,
				HostName: "127.0.0.1",
				CertName: fmt.Sprintf("sha256-raw:%-02x", sha256.Sum256(cert.Leaf.Raw)),
				DERPPort: lnPort,
			},
		},
	}

	netMon := netmon.NewStatic()
	dc := derphttp.NewRegionClient(key.NewNode(), t.Logf, netMon, func() *tailcfg.DERPRegion {
		return reg
	})
	defer dc.Close()

	_, connClose, _, err := dc.DialRegionTLS(context.Background(), reg)
	if err != nil {
		t.Fatalf("DialRegionTLS: %v", err)
	}
	defer connClose.Close()
}
