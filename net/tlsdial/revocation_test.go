// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tlsdial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// newTestChain returns a leaf certificate for dnsName and a pool holding the
// self-signed root that issued it.
func newTestChain(t *testing.T, dnsName string) (leaf *x509.Certificate, roots *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlsdial test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(root)
	return leaf, roots
}

func TestHookCheckRevocation(t *testing.T) {
	const host = "revoked.test"
	leaf, roots := newTestChain(t, host)

	errRevoked := errors.New("revoked")
	var gotName string
	var gotChain []*x509.Certificate
	var revoked bool
	defer HookCheckRevocation.SetForTest(func(dnsName string, chain []*x509.Certificate) error {
		gotName, gotChain = dnsName, chain
		if revoked {
			return errRevoked
		}
		return nil
	})()

	tests := []struct {
		name   string
		verify func() error
	}{
		{"Config", func() error {
			conf := Config(nil, &tls.Config{RootCAs: roots})
			return conf.VerifyConnection(tls.ConnectionState{
				ServerName:       host,
				PeerCertificates: []*x509.Certificate{leaf},
			})
		}},
		{"SetConfigExpectedCert", func() error {
			conf := &tls.Config{ServerName: "front.test", RootCAs: roots}
			SetConfigExpectedCert(conf, host)
			return conf.VerifyPeerCertificate([][]byte{leaf.Raw}, nil)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, revoked = range []bool{false, true} {
				gotName, gotChain = "", nil
				err := tt.verify()
				if revoked && !errors.Is(err, errRevoked) {
					t.Errorf("revoked: got err %v; want %v", err, errRevoked)
				}
				if !revoked && err != nil {
					t.Errorf("not revoked: got err %v; want nil", err)
				}
				if gotName != host {
					t.Errorf("hook got name %q; want %q", gotName, host)
				}
				if len(gotChain) != 2 || !gotChain[0].Equal(leaf) {
					t.Errorf("hook got chain of len %d; want leaf + root", len(gotChain))
				}
			}
		})
	}
}
