// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package ipnlocal

import (
	"crypto/x509"
	"embed"
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
