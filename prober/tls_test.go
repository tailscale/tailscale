// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var leafCert = x509.Certificate{
	SerialNumber:       big.NewInt(10001),
	Subject:            pkix.Name{CommonName: "tlsprobe.test"},
	SignatureAlgorithm: x509.SHA256WithRSA,
	PublicKeyAlgorithm: x509.RSA,
	Version:            3,
	IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	NotBefore:          time.Now().Add(-5 * time.Minute),
	NotAfter:           time.Now().Add(60 * 24 * time.Hour),
	SubjectKeyId:       []byte{1, 2, 3},
	AuthorityKeyId:     []byte{1, 2, 3, 4, 5}, // issuerCert below
	ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:           x509.KeyUsageDigitalSignature,
}

var issuerCertTpl = x509.Certificate{
	SerialNumber:       big.NewInt(10002),
	Subject:            pkix.Name{CommonName: "tlsprobe.ca.test"},
	SignatureAlgorithm: x509.SHA256WithRSA,
	PublicKeyAlgorithm: x509.RSA,
	Version:            3,
	IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	NotBefore:          time.Now().Add(-5 * time.Minute),
	NotAfter:           time.Now().Add(60 * 24 * time.Hour),
	SubjectKeyId:       []byte{1, 2, 3, 4, 5},
	ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:           x509.KeyUsageDigitalSignature,
}

func simpleCert() (tls.Certificate, error) {
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certBytes, err := x509.CreateCertificate(rand.Reader, &leafCert, &leafCert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
}

func TestTLSConnection(t *testing.T) {
	crt, err := simpleCert()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{crt}}
	srv.StartTLS()
	defer srv.Close()

	err = probeTLS(context.Background(), "fail.example.com", srv.Listener.Addr().String())
	// The specific error message here is platform-specific ("certificate is not trusted"
	// on macOS and "certificate signed by unknown authority" on Linux), so only check
	// that it contains the word 'certificate'.
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unexpected error: %q", err)
	}
}

func TestCertExpiration(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cert    func() *x509.Certificate
		wantErr string
	}{
		{
			"cert not valid yet",
			func() *x509.Certificate {
				c := leafCert
				c.NotBefore = time.Now().Add(time.Hour)
				return &c
			},
			"one of the certs has NotBefore in the future",
		},
		{
			"cert expiring soon",
			func() *x509.Certificate {
				c := leafCert
				c.NotAfter = time.Now().Add(time.Hour)
				return &c
			},
			"one of the certs expires in",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tt.cert()}}
			err := validateConnState(context.Background(), cs)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("unexpected error %q; want %q", err, tt.wantErr)
			}
		})
	}
}

type CRLServer struct {
	crlBytes []byte
}

func (s *CRLServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.crlBytes == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(s.crlBytes)
}

func TestCRL(t *testing.T) {
	// Generate CA key and self-signed CA cert
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := issuerCertTpl
	caTpl.BasicConstraintsValid = true
	caTpl.IsCA = true
	caTpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTpl, &caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Issue a leaf cert signed by the CA
	leaf := leafCert
	leaf.SerialNumber = big.NewInt(20001)
	leaf.Issuer = caCert.Subject
	leafKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, &leaf, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertParsed, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Catch no CRL set by Let's Encrypt date.
	noCRLCert := leafCert
	noCRLCert.SerialNumber = big.NewInt(20002)
	noCRLCert.CRLDistributionPoints = []string{}
	noCRLCert.NotBefore = time.Unix(letsEncryptStartedStaplingCRL, 0).Add(-48 * time.Hour)
	noCRLCert.Issuer = caCert.Subject
	noCRLCertKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	noCRLStapledBytes, err := x509.CreateCertificate(rand.Reader, &noCRLCert, caCert, &noCRLCertKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	noCRLStapledParsed, err := x509.ParseCertificate(noCRLStapledBytes)
	if err != nil {
		t.Fatal(err)
	}

	crlServer := &CRLServer{crlBytes: nil}
	srv := httptest.NewServer(crlServer)
	defer srv.Close()

	// Create a CRL that revokes the leaf cert using x509.CreateRevocationList
	now := time.Now()
	revoked := []x509.RevocationListEntry{{
		SerialNumber:   leaf.SerialNumber,
		RevocationTime: now,
		ReasonCode:     1, // Key compromise
	}}
	rl := x509.RevocationList{
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		Issuer:                    caCert.Subject,
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
		Number:                    big.NewInt(1),
	}
	rlBytes, err := x509.CreateRevocationList(rand.Reader, &rl, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}

	emptyRlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2)}, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name     string
		cert     *x509.Certificate
		crlBytes []byte
		wantErr  string
	}{
		{
			"ValidCert",
			leafCertParsed,
			emptyRlBytes,
			"",
		},
		{
			"RevokedCert",
			leafCertParsed,
			rlBytes,
			"has been revoked on",
		},
		{
			"EmptyCRL",
			leafCertParsed,
			emptyRlBytes,
			"",
		},
		{
			"NoCRL",
			leafCertParsed,
			nil,
			"no CRL server presented in leaf cert for",
		},
		{
			"NotBeforeCRLStaplingDate",
			noCRLStapledParsed,
			nil,
			"",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tt.cert, caCert}}
			if tt.crlBytes != nil {
				crlServer.crlBytes = tt.crlBytes
				tt.cert.CRLDistributionPoints = []string{srv.URL}
			} else {
				crlServer.crlBytes = nil
				tt.cert.CRLDistributionPoints = []string{}
			}
			err := validateConnState(context.Background(), cs)

			if err == nil && tt.wantErr == "" {
				return
			}

			if err == nil || tt.wantErr == "" || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("unexpected error %q; want %q", err, tt.wantErr)
			}
		})
	}
}
