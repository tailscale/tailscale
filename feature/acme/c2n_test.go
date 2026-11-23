// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package acme

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

func TestHandleC2NTLSCertStatus(t *testing.T) {
	// A non-default ACME URL makes validateLeaf accept the untrusted-ca cert.
	t.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", "")
	b := ipnlocaltest.NewBackend(t)
	b.SetVarRoot(t.TempDir())
	e := extOf(t, b)

	certDirPath, err := certDir(b)
	if err != nil {
		t.Fatalf("certDir error: %v", err)
	}
	if _, err := e.getCertStore(b); err != nil {
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

	untrustedCert, untrustedKey := untrustedPair(t, "example.com",
		time.Date(2023, time.February, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2025, time.May, 1, 0, 0, 0, 0, time.UTC))

	tests := []struct {
		name       string
		domain     string
		copyFile   bool   // copy testdata/example.com.pem to the certDir
		certPEM    []byte // if non-nil, copied in place of the testdata cert
		keyPEM     []byte // if non-nil, copied in place of the testdata key
		wantStatus int    // 0 means 200
		wantError  string // wanted non-JSON non-200 error
		now        time.Time
		want       *tailcfg.C2NTLSCertInfo
	}{
		{
			name:       "no-domain",
			wantStatus: 400,
			wantError:  "no 'domain'\n",
		},
		{
			name:   "missing",
			domain: "example.com",
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "no certificate",
				Missing: true,
			},
		},
		{
			name:     "valid",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Valid:     true,
				NotBefore: "2023-02-07T20:34:18Z",
				NotAfter:  "2025-05-07T19:34:18Z",
			},
		},
		{
			name:     "expired",
			domain:   "example.com",
			now:      time.Date(2030, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "cert expired",
				Expired: true,
			},
		},
		{
			name:     "not-yet-valid",
			domain:   "example.com",
			now:      time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Error: "cert invalid: x509: certificate has expired or is not yet valid: current time 2023-01-01T00:00:00Z is before 2023-02-07T20:34:18Z",
			},
		},
		{
			name:     "untrusted-ca",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			certPEM:  untrustedCert,
			keyPEM:   untrustedKey,
			want: &tailcfg.C2NTLSCertInfo{
				Error: "cert invalid: x509: certificate signed by unknown authority",
			},
		},
		{
			name:     "expired-untrusted-ca",
			domain:   "example.com",
			now:      time.Date(2030, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			certPEM:  untrustedCert,
			keyPEM:   untrustedKey,
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "cert expired",
				Expired: true,
			},
		},
		{
			name:     "name-mismatch",
			domain:   "other.example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Error: "cert invalid: x509: certificate is valid for example.com, not other.example.com",
			},
		},
		{
			name:     "key-mismatch",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			keyPEM:   untrustedKey,
			want: &tailcfg.C2NTLSCertInfo{
				Error: "cert invalid: tls: private key type does not match public key type",
			},
		},
		{
			name:     "bad-pem",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			certPEM:  []byte("not a cert"),
			want: &tailcfg.C2NTLSCertInfo{
				Error: "cert invalid: tls: failed to find any PEM data in certificate input",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.RemoveAll(certDirPath) // reset per test
			if tt.copyFile {
				certPEM := must.Get(certTestFS.ReadFile("testdata/example.com.pem"))
				if tt.certPEM != nil {
					certPEM = tt.certPEM
				}
				keyPEM := must.Get(certTestFS.ReadFile("testdata/example.com-key.pem"))
				if tt.keyPEM != nil {
					keyPEM = tt.keyPEM
				}
				os.MkdirAll(certDirPath, 0755)
				if err := os.WriteFile(certFile(certDirPath, tt.domain), certPEM, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyFile(certDirPath, tt.domain), keyPEM, 0644); err != nil {
					t.Fatal(err)
				}
			}
			b.ForTest().SetClock(tstest.NewClock(tstest.ClockOpts{
				Start: tt.now,
			}))

			rec := httptest.NewRecorder()
			e.handleC2NTLSCertStatus(b, rec, httptest.NewRequest("GET", "/tls-cert-status?domain="+url.QueryEscape(tt.domain), nil))
			res := rec.Result()
			wantStatus := cmp.Or(tt.wantStatus, 200)
			if res.StatusCode != wantStatus {
				t.Fatalf("status code = %v; want %v. Body: %s", res.Status, wantStatus, rec.Body.Bytes())
			}
			if wantStatus == 200 {
				var got tailcfg.C2NTLSCertInfo
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("bad JSON: %v", err)
				}
				if !reflect.DeepEqual(&got, tt.want) {
					t.Errorf("got %v; want %v", logger.AsJSON(got), logger.AsJSON(tt.want))
				}
				// The localapi cert-status endpoint reads the same cache via LocalBackend.CertStatus.
				gotLocal, err := b.CertStatus(tt.domain)
				if err != nil {
					t.Fatalf("CertStatus: %v", err)
				}
				if !reflect.DeepEqual(gotLocal, tt.want) {
					t.Errorf("CertStatus = %v; want %v", logger.AsJSON(gotLocal), logger.AsJSON(tt.want))
				}
				// An unusable cached cert must get past getCertPEM's cached-cert check; ctx is canceled so nothing is issued.
				if !tt.want.Valid {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					_, err := getCertPEM(ctx, e, b, must.Get(e.getCertStore(b)), t.Logf, func(any) {}, tt.domain, tt.now, 0)
					if !errors.Is(err, context.Canceled) {
						t.Errorf("getCertPEM error = %v; want context.Canceled from past the cached-cert check", err)
					}
				}
			} else if tt.wantError != "" {
				if got := rec.Body.String(); got != tt.wantError {
					t.Errorf("body = %q; want %q", got, tt.wantError)
				}
			}
		})
	}
}

// untrustedPair returns a self-signed cert and key for domain, valid from
// notBefore to notAfter, that no test root pool trusts.
func untrustedPair(t *testing.T, domain string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	var key bytes.Buffer
	if err := encodeECDSAKey(&key, priv); err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key.Bytes()
}
