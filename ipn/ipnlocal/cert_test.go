// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package ipnlocal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/store/mem"
)

func TestValidLookingCertDomain(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"foo.com", true},
		{"foo..com", false},
		{"foo/com.com", false},
		{"NUL", false},
		{"", false},
		{"foo\\bar.com", false},
		{"foo\x00bar.com", false},
	}
	for _, tt := range tests {
		if got := validLookingCertDomain(tt.in); got != tt.want {
			t.Errorf("validLookingCertDomain(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

//go:embed testdata/*
var certTestFS embed.FS

func TestCertStoreRoundTrip(t *testing.T) {
	const testDomain = "example.com"

	// Use a fixed verification timestamp so validity doesn't fall off when the
	// cert expires. If you update the test data below, this may also need to be
	// updated.
	testNow := time.Date(2023, time.February, 10, 0, 0, 0, 0, time.UTC)

	// To re-generate a root certificate and domain certificate for testing,
	// use:
	//
	//   	go run filippo.io/mkcert@latest example.com
	//
	// The content is not important except to be structurally valid so we can be
	// sure the round-trip succeeds.
	testRoot, err := certTestFS.ReadFile("testdata/rootCA.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(testRoot) {
		t.Fatal("Unable to add test CA to the cert pool")
	}

	testCert, err := certTestFS.ReadFile("testdata/example.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	testKey, err := certTestFS.ReadFile("testdata/example.com-key.pem")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		store certStore
	}{
		{"FileStore", certFileStore{dir: t.TempDir(), testRoots: roots}},
		{"StateStore", certStateStore{StateStore: new(mem.Store), testRoots: roots}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.store.WriteCert(testDomain, testCert); err != nil {
				t.Fatalf("WriteCert: unexpected error: %v", err)
			}
			if err := test.store.WriteKey(testDomain, testKey); err != nil {
				t.Fatalf("WriteKey: unexpected error: %v", err)
			}

			kp, err := test.store.Read(testDomain, testNow)
			if err != nil {
				t.Fatalf("Read: unexpected error: %v", err)
			}
			if diff := cmp.Diff(kp.CertPEM, testCert); diff != "" {
				t.Errorf("Certificate (-got, +want):\n%s", diff)
			}
			if diff := cmp.Diff(kp.KeyPEM, testKey); diff != "" {
				t.Errorf("Key (-got, +want):\n%s", diff)
			}
		})
	}
}

func TestShouldStartDomainRenewal(t *testing.T) {
	reset := func() {
		renewMu.Lock()
		defer renewMu.Unlock()
		clear(renewCertAt)
	}

	mustMakePair := func(template *x509.Certificate) *TLSCertKeyPair {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		b, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			panic(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		})

		return &TLSCertKeyPair{
			Cached:  false,
			CertPEM: certPEM,
			KeyPEM:  []byte("unused"),
		}
	}

	now := time.Unix(1685714838, 0)
	subject := pkix.Name{
		Organization:  []string{"Tailscale, Inc."},
		Country:       []string{"CA"},
		Province:      []string{"ON"},
		Locality:      []string{"Toronto"},
		StreetAddress: []string{"290 Bremner Blvd"},
		PostalCode:    []string{"M5V 3L9"},
	}

	testCases := []struct {
		name      string
		notBefore time.Time
		lifetime  time.Duration
		want      bool
		wantErr   string
	}{
		{
			name:      "should renew",
			notBefore: now.AddDate(0, 0, -89),
			lifetime:  90 * 24 * time.Hour,
			want:      true,
		},
		{
			name:      "short-lived renewal",
			notBefore: now.AddDate(0, 0, -7),
			lifetime:  10 * 24 * time.Hour,
			want:      true,
		},
		{
			name:      "no renew",
			notBefore: now.AddDate(0, 0, -59), // 59 days ago == not 2/3rds of the way through 90 days yet
			lifetime:  90 * 24 * time.Hour,
			want:      false,
		},
	}
	b := new(LocalBackend)
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			reset()

			ret, err := b.domainRenewalTimeByExpiry(mustMakePair(&x509.Certificate{
				SerialNumber: big.NewInt(2019),
				Subject:      subject,
				NotBefore:    tt.notBefore,
				NotAfter:     tt.notBefore.Add(tt.lifetime),
			}))

			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("wanted error, got nil")
				} else if err.Error() != tt.wantErr {
					t.Errorf("got err=%q, want %q", err.Error(), tt.wantErr)
				}
			} else {
				renew := now.After(ret)
				if renew != tt.want {
					t.Errorf("got renew=%v (ret=%v), want renew %v", renew, ret, tt.want)
				}
			}
		})
	}
}

func TestDebugACMEDirectoryURL(t *testing.T) {
	for _, tc := range []string{"", "https://acme-staging-v02.api.letsencrypt.org/directory"} {
		const setting = "TS_DEBUG_ACME_DIRECTORY_URL"
		t.Run(tc, func(t *testing.T) {
			t.Setenv(setting, tc)
			ac, err := acmeClient(certStateStore{StateStore: new(mem.Store)})
			if err != nil {
				t.Fatalf("acmeClient creation err: %v", err)
			}
			if ac.DirectoryURL != tc {
				t.Fatalf("acmeClient.DirectoryURL = %q, want %q", ac.DirectoryURL, tc)
			}
		})
	}
}
