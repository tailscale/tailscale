// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"context"
	"crypto"
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

	"golang.org/x/crypto/ocsp"
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
		{
			"valid duration but no OCSP",
			func() *x509.Certificate { return &leafCert },
			"no OCSP server presented in leaf cert for CN=tlsprobe.test",
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

type ocspServer struct {
	issuer        *x509.Certificate
	responderCert *x509.Certificate
	template      *ocsp.Response
	priv          crypto.Signer
}

func (s *ocspServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.template == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp, err := ocsp.CreateResponse(s.issuer, s.responderCert, *s.template, s.priv)
	if err != nil {
		panic(err)
	}
	w.Write(resp)
}

func TestOCSP(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerCertTpl, &issuerCertTpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	responderKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	// issuer cert template re-used here, but with a different key
	responderBytes, err := x509.CreateCertificate(rand.Reader, &issuerCertTpl, &issuerCertTpl, &responderKey.PublicKey, responderKey)
	if err != nil {
		t.Fatal(err)
	}
	responderCert, err := x509.ParseCertificate(responderBytes)
	if err != nil {
		t.Fatal(err)
	}

	handler := &ocspServer{
		issuer:        issuerCert,
		responderCert: responderCert,
		priv:          issuerKey,
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Start()
	defer srv.Close()

	cert := leafCert
	cert.OCSPServer = append(cert.OCSPServer, srv.URL)
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name    string
		resp    *ocsp.Response
		wantErr string
	}{
		{"good response", &ocsp.Response{Status: ocsp.Good}, ""},
		{"unknown response", &ocsp.Response{Status: ocsp.Unknown}, "unknown OCSP verification status for CN=tlsprobe.test"},
		{"revoked response", &ocsp.Response{Status: ocsp.Revoked}, "cert for CN=tlsprobe.test has been revoked"},
		{"error 500 from ocsp", nil, "non-200 status code from OCSP"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler.template = tt.resp
			if handler.template != nil {
				handler.template.SerialNumber = big.NewInt(1337)
			}
			cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed, issuerCert}}
			err := validateConnState(context.Background(), cs)

			if err == nil && tt.wantErr == "" {
				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("unexpected error %q; want %q", err, tt.wantErr)
			}
		})
	}
}
