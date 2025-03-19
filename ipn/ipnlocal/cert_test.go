// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package ipnlocal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/envknob"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
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

	// Use fixed verification timestamps so validity doesn't change over time.
	// If you update the test data below, these may also need to be updated.
	testNow := time.Date(2023, time.February, 10, 0, 0, 0, 0, time.UTC)
	testExpired := time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)

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
		name         string
		store        certStore
		debugACMEURL bool
	}{
		{"FileStore", certFileStore{dir: t.TempDir(), testRoots: roots}, false},
		{"FileStore_UnknownCA", certFileStore{dir: t.TempDir()}, true},
		{"StateStore", certStateStore{StateStore: new(mem.Store), testRoots: roots}, false},
		{"StateStore_UnknownCA", certStateStore{StateStore: new(mem.Store)}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.debugACMEURL {
				t.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
			}
			if err := test.store.WriteTLSCertAndKey(testDomain, testCert, testKey); err != nil {
				t.Fatalf("WriteTLSCertAndKey: unexpected error: %v", err)
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
			unexpected, err := test.store.Read(testDomain, testExpired)
			if err != errCertExpired {
				t.Fatalf("Read: expected expiry error: %v", string(unexpected.CertPEM))
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

func TestGetCertPEMWithValidity(t *testing.T) {
	const testDomain = "example.com"
	b := &LocalBackend{
		store:   &mem.Store{},
		varRoot: t.TempDir(),
		ctx:     context.Background(),
		logf:    t.Logf,
	}
	certDir, err := b.certDir()
	if err != nil {
		t.Fatalf("certDir error: %v", err)
	}
	if _, err := b.getCertStore(); err != nil {
		t.Fatalf("getCertStore error: %v", err)
	}
	testRoot, err := certTestFS.ReadFile("testdata/rootCA.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(testRoot) {
		t.Fatal("Unable to add test CA to the cert pool")
	}
	testX509Roots = roots
	defer func() { testX509Roots = nil }()
	tests := []struct {
		name string
		now  time.Time
		// storeCerts is true if the test cert and key should be written to store.
		storeCerts       bool
		readOnlyMode     bool // TS_READ_ONLY_CERTS env var
		wantAsyncRenewal bool // async issuance should be started
		wantIssuance     bool // sync issuance should be started
		wantErr          bool
	}{
		{
			name:             "valid_no_renewal",
			now:              time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			storeCerts:       true,
			wantAsyncRenewal: false,
			wantIssuance:     false,
			wantErr:          false,
		},
		{
			name:             "issuance_needed",
			now:              time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			storeCerts:       false,
			wantAsyncRenewal: false,
			wantIssuance:     true,
			wantErr:          false,
		},
		{
			name:             "renewal_needed",
			now:              time.Date(2025, time.May, 1, 0, 0, 0, 0, time.UTC),
			storeCerts:       true,
			wantAsyncRenewal: true,
			wantIssuance:     false,
			wantErr:          false,
		},
		{
			name:             "renewal_needed_read_only_mode",
			now:              time.Date(2025, time.May, 1, 0, 0, 0, 0, time.UTC),
			storeCerts:       true,
			readOnlyMode:     true,
			wantAsyncRenewal: false,
			wantIssuance:     false,
			wantErr:          false,
		},
		{
			name:             "no_certs_read_only_mode",
			now:              time.Date(2025, time.May, 1, 0, 0, 0, 0, time.UTC),
			storeCerts:       false,
			readOnlyMode:     true,
			wantAsyncRenewal: false,
			wantIssuance:     false,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.readOnlyMode {
				envknob.Setenv("TS_CERT_SHARE_MODE", "ro")
			}

			os.RemoveAll(certDir)
			if tt.storeCerts {
				os.MkdirAll(certDir, 0755)
				if err := os.WriteFile(filepath.Join(certDir, "example.com.crt"),
					must.Get(os.ReadFile("testdata/example.com.pem")), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(certDir, "example.com.key"),
					must.Get(os.ReadFile("testdata/example.com-key.pem")), 0644); err != nil {
					t.Fatal(err)
				}
			}

			b.clock = tstest.NewClock(tstest.ClockOpts{Start: tt.now})

			allDone := make(chan bool, 1)
			defer b.goTracker.AddDoneCallback(func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				if b.goTracker.RunningGoroutines() > 0 {
					return
				}
				select {
				case allDone <- true:
				default:
				}
			})()

			// Set to true if get getCertPEM is called. GetCertPEM can be called in a goroutine for async
			// renewal or in the main goroutine if issuance is required to obtain valid TLS credentials.
			getCertPemWasCalled := false
			getCertPEM = func(ctx context.Context, b *LocalBackend, cs certStore, logf logger.Logf, traceACME func(any), domain string, now time.Time, minValidity time.Duration) (*TLSCertKeyPair, error) {
				getCertPemWasCalled = true
				return nil, nil
			}
			prevGoRoutines := b.goTracker.StartedGoroutines()
			_, err = b.GetCertPEMWithValidity(context.Background(), testDomain, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("b.GetCertPemWithValidity got err %v, wants error: '%v'", err, tt.wantErr)
			}
			// GetCertPEMWithValidity calls getCertPEM in a goroutine if async renewal is needed. That's the
			// only goroutine it starts, so this can be used to test if async renewal was started.
			gotAsyncRenewal := b.goTracker.StartedGoroutines()-prevGoRoutines != 0
			if gotAsyncRenewal {
				select {
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for goroutines to finish")
				case <-allDone:
				}
			}
			// Verify that async renewal was triggered if expected.
			if tt.wantAsyncRenewal != gotAsyncRenewal {
				t.Fatalf("wants getCertPem to be called async: %v, got called %v", tt.wantAsyncRenewal, gotAsyncRenewal)
			}
			// Verify that (non-async) issuance was started if expected.
			gotIssuance := getCertPemWasCalled && !gotAsyncRenewal
			if tt.wantIssuance != gotIssuance {
				t.Errorf("wants getCertPem to be called: %v, got called %v", tt.wantIssuance, gotIssuance)
			}
		})
	}
}
