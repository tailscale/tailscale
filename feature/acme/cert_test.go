// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	xacme "tailscale.com/tempfork/acme"
	"tailscale.com/tsconst"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

//go:embed testdata/*
var certTestFS embed.FS

// extOf returns the [*extension] registered on b, failing the test if
// it's not present.
func extOf(t *testing.T, b *ipnlocal.LocalBackend) *extension {
	t.Helper()
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		t.Fatal("acme extension not registered on backend")
	}
	return e
}

func TestCertRequest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		wantSANs []string
	}{
		{
			name:     "example-com",
			domain:   "example.com",
			wantSANs: []string{"example.com"},
		},
		{
			name:     "wildcard-example-com",
			domain:   "*.example.com",
			wantSANs: []string{"*.example.com", "example.com"},
		},
		{
			name:     "wildcard-foo-bar-com",
			domain:   "*.foo.bar.com",
			wantSANs: []string{"*.foo.bar.com", "foo.bar.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrDER, err := certRequest(key, tt.domain, nil)
			if err != nil {
				t.Fatalf("certRequest: %v", err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatalf("ParseCertificateRequest: %v", err)
			}
			if csr.Subject.CommonName != tt.domain {
				t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, tt.domain)
			}
			if !slices.Equal(csr.DNSNames, tt.wantSANs) {
				t.Errorf("DNSNames = %v, want %v", csr.DNSNames, tt.wantSANs)
			}
		})
	}
}

func TestResolveCertDomain(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		certDomains []string
		hasCap      bool
		skipNetmap  bool
		want        string
		wantErr     string
	}{
		{
			name:        "exact_match",
			domain:      "node.ts.net",
			certDomains: []string{"node.ts.net"},
			want:        "node.ts.net",
		},
		{
			name:        "exact_match_with_cap",
			domain:      "node.ts.net",
			certDomains: []string{"node.ts.net"},
			hasCap:      true,
			want:        "node.ts.net",
		},
		{
			name:        "wildcard_with_cap",
			domain:      "*.node.ts.net",
			certDomains: []string{"node.ts.net"},
			hasCap:      true,
			want:        "*.node.ts.net",
		},
		{
			name:        "wildcard_without_cap",
			domain:      "*.node.ts.net",
			certDomains: []string{"node.ts.net"},
			wantErr:     "wildcard certificates are not enabled for this node",
		},
		{
			name:        "wildcard_wrong_domain_with_cap",
			domain:      "*.other.com",
			certDomains: []string{"node.ts.net"},
			hasCap:      true,
			wantErr:     `invalid domain "*.other.com"; wildcard certificates are not enabled for this domain`,
		},
		{
			name:        "missing_domain",
			domain:      "",
			certDomains: []string{"node.ts.net"},
			wantErr:     "missing domain name",
		},
		{
			name:        "no_cert_domains_with_cap",
			domain:      "node.ts.net",
			certDomains: nil,
			hasCap:      true,
			wantErr:     "your Tailscale account does not support getting TLS certs",
		},
		{
			name:        "no_cert_domains_without_cap",
			domain:      "node.ts.net",
			certDomains: nil,
			wantErr:     "your Tailscale account does not support getting TLS certs",
		},
		{
			name:        "subdomain_request_rejected_without_cap",
			domain:      "app.node.ts.net",
			certDomains: []string{"node.ts.net"},
			wantErr:     `invalid domain "app.node.ts.net"; must be one of ["node.ts.net"]`,
		},
		{
			name:        "subdomain_request_rejected_with_cap",
			domain:      "app.node.ts.net",
			certDomains: []string{"node.ts.net"},
			hasCap:      true,
			wantErr:     `invalid domain "app.node.ts.net"; must be one of ["node.ts.net"]`,
		},
		{
			name:       "nil_netmap",
			domain:     "node.ts.net",
			skipNetmap: true,
			wantErr:    "no netmap available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := ipnlocaltest.NewBackend(t)
			e := extOf(t, b)

			if !tt.skipNetmap {
				var allCaps set.Set[tailcfg.NodeCapability]
				if tt.hasCap {
					allCaps = set.Of(tailcfg.NodeAttrDNSSubdomainResolve)
				}
				b.ForTest().SetNetMap(&netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{}).View(),
					DNS: tailcfg.DNSConfig{
						CertDomains: tt.certDomains,
					},
					AllCaps: allCaps,
				})
			}

			got, err := e.resolveCertDomain(b, tt.domain)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("resolveCertDomain(%q) = %q, want error %q", tt.domain, got, tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("resolveCertDomain(%q) error = %q, want %q", tt.domain, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("resolveCertDomain(%q) error = %v, want nil", tt.domain, err)
				return
			}
			if got != tt.want {
				t.Errorf("resolveCertDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

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
		// Wildcard tests
		{"*.foo.com", true},
		{"*.foo.bar.com", true},
		{"*foo.com", false},      // must be *.
		{"*.com", false},         // must have domain after *.
		{"*.", false},            // must have domain after *.
		{"*.*.foo.com", false},   // no nested wildcards
		{"foo.*.bar.com", false}, // no wildcard mid-string
		{"app.foo.com", true},    // regular subdomain
		{"*", false},             // bare asterisk
	}
	for _, tt := range tests {
		if got := validLookingCertDomain(tt.in); got != tt.want {
			t.Errorf("validLookingCertDomain(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestACMETLSALPNCertHook(t *testing.T) {
	b := ipnlocaltest.NewBackend(t)
	e := extOf(t, b)
	cert := &tls.Certificate{}
	cleanup := e.storeACMETLSALPNCert("example.com", cert)
	defer cleanup()

	if got, ok := b.ForTest().GetACMETLSALPNCert(&tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{xacme.ALPNProto},
	}); !ok || got != cert {
		t.Fatalf("getACMETLSALPNCert = %v, %v; want stored cert, true", got, ok)
	}
	if _, ok := b.ForTest().GetACMETLSALPNCert(&tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{"http/1.1"},
	}); ok {
		t.Fatal("getACMETLSALPNCert without acme ALPN = ok, want false")
	}
	if _, ok := b.ForTest().GetACMETLSALPNCert(&tls.ClientHelloInfo{
		ServerName:      "other.example.com",
		SupportedProtos: []string{xacme.ALPNProto},
	}); ok {
		t.Fatal("getACMETLSALPNCert for other name = ok, want false")
	}

	otherBackend := ipnlocaltest.NewBackend(t)
	if _, ok := otherBackend.ForTest().GetACMETLSALPNCert(&tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{xacme.ALPNProto},
	}); ok {
		t.Fatal("getACMETLSALPNCert on different LocalBackend = ok, want false")
	}
}

func TestShouldUseACMETLSALPN01(t *testing.T) {
	const (
		tsNetDomain = "node.ts.net"
		byoDomain   = "foo.com"
	)
	previous := &ipnlocal.TLSCertKeyPair{}

	setFunnel := func(b *ipnlocal.LocalBackend, hosts ...string) {
		funnel := map[ipn.HostPort]bool{}
		for _, h := range hosts {
			funnel[ipn.HostPort(h+":443")] = true
		}
		b.ForTest().SetServeConfig((&ipn.ServeConfig{AllowFunnel: funnel}).View())
	}
	setNetmap := func(b *ipnlocal.LocalBackend, certDomains ...string) {
		b.ForTest().SetNetMap(&netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{}).View(),
			DNS:      tailcfg.DNSConfig{CertDomains: certDomains},
		})
	}

	tests := []struct {
		name     string
		domain   string
		previous *ipnlocal.TLSCertKeyPair
		funnel   []string
		netmap   []string // CertDomains; if nil, no netmap installed
		want     bool
	}{
		{
			name:     "tsnet_renewal",
			domain:   tsNetDomain,
			previous: previous,
			funnel:   []string{tsNetDomain},
			netmap:   []string{tsNetDomain},
			want:     true,
		},
		{
			name:     "tsnet_first_issuance_prefers_dns01",
			domain:   tsNetDomain,
			previous: nil,
			funnel:   []string{tsNetDomain},
			netmap:   []string{tsNetDomain},
			want:     false,
		},
		{
			name:     "tsnet_wildcard_rejected",
			domain:   "*." + tsNetDomain,
			previous: previous,
			funnel:   []string{tsNetDomain},
			netmap:   []string{tsNetDomain},
			want:     false,
		},
		{
			name:     "tsnet_without_funnel_rejected",
			domain:   tsNetDomain,
			previous: previous,
			funnel:   nil,
			netmap:   []string{tsNetDomain},
			want:     false,
		},
		{
			name:     "byo_first_issuance_uses_alpn",
			domain:   byoDomain,
			previous: nil,
			funnel:   []string{byoDomain},
			netmap:   []string{tsNetDomain},
			want:     true,
		},
		{
			name:     "byo_renewal_uses_alpn",
			domain:   byoDomain,
			previous: previous,
			funnel:   []string{byoDomain},
			netmap:   []string{tsNetDomain},
			want:     true,
		},
		{
			name:     "byo_without_funnel_rejected",
			domain:   byoDomain,
			previous: previous,
			funnel:   nil,
			netmap:   []string{tsNetDomain},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := ipnlocaltest.NewBackend(t)
			e := extOf(t, b)
			if tt.netmap != nil {
				setNetmap(b, tt.netmap...)
			}
			setFunnel(b, tt.funnel...)
			if got := e.shouldUseACMETLSALPN01(b, tt.domain, tt.previous, t.Logf); got != tt.want {
				t.Errorf("shouldUseACMETLSALPN01(%q, previous=%v) = %v, want %v",
					tt.domain, tt.previous != nil, got, tt.want)
			}
		})
	}
}

func TestIsBYOFunnelDomain(t *testing.T) {
	setFunnel := func(b *ipnlocal.LocalBackend, hosts ...string) {
		funnel := map[ipn.HostPort]bool{}
		for _, h := range hosts {
			funnel[ipn.HostPort(h+":443")] = true
		}
		b.ForTest().SetServeConfig((&ipn.ServeConfig{AllowFunnel: funnel}).View())
	}
	setNetmap := func(b *ipnlocal.LocalBackend, certDomains ...string) {
		b.ForTest().SetNetMap(&netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{}).View(),
			DNS:      tailcfg.DNSConfig{CertDomains: certDomains},
		})
	}

	tests := []struct {
		name        string
		domain      string
		certDomains []string
		funnel      []string
		want        bool
	}{
		{name: "byo_with_funnel", domain: "foo.com", certDomains: []string{"node.ts.net"}, funnel: []string{"foo.com"}, want: true},
		{name: "byo_without_funnel", domain: "foo.com", certDomains: []string{"node.ts.net"}, want: false},
		{name: "tsnet_exact_match_not_byo", domain: "node.ts.net", certDomains: []string{"node.ts.net"}, funnel: []string{"node.ts.net"}, want: false},
		{name: "wildcard_never_byo", domain: "*.foo.com", certDomains: []string{"node.ts.net"}, funnel: []string{"foo.com"}, want: false},
		{name: "empty_never_byo", domain: "", certDomains: []string{"node.ts.net"}, funnel: []string{"foo.com"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := ipnlocaltest.NewBackend(t)
			e := extOf(t, b)
			setNetmap(b, tt.certDomains...)
			setFunnel(b, tt.funnel...)
			if got := e.isBYOFunnelDomain(b, tt.domain); got != tt.want {
				t.Errorf("isBYOFunnelDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestResolveCertDomainBYO(t *testing.T) {
	const (
		tsNetDomain = "node.ts.net"
		byoDomain   = "foo.com"
	)
	b := ipnlocaltest.NewBackend(t)
	e := extOf(t, b)
	b.ForTest().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{}).View(),
		DNS:      tailcfg.DNSConfig{CertDomains: []string{tsNetDomain}},
	})

	// Without a serve config, BYO is rejected.
	if _, err := e.resolveCertDomain(b, byoDomain); err == nil {
		t.Fatalf("resolveCertDomain(%q) without serve config: want error, got nil", byoDomain)
	}

	// Web entry alone (no AllowFunnel) is not enough; the gate is Funnel.
	b.ForTest().SetServeConfig((&ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			byoDomain + ":443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://127.0.0.1:8080"}}},
		},
	}).View())
	if _, err := e.resolveCertDomain(b, byoDomain); err == nil {
		t.Fatalf("resolveCertDomain(%q) with Web but no Funnel: want error, got nil", byoDomain)
	}

	// With AllowFunnel, BYO is accepted.
	b.ForTest().SetServeConfig((&ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			byoDomain + ":443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://127.0.0.1:8080"}}},
		},
		AllowFunnel: map[ipn.HostPort]bool{byoDomain + ":443": true},
	}).View())
	got, err := e.resolveCertDomain(b, byoDomain)
	if err != nil {
		t.Fatalf("resolveCertDomain(%q): %v", byoDomain, err)
	}
	if got != byoDomain {
		t.Errorf("resolveCertDomain(%q) = %q, want %q", byoDomain, got, byoDomain)
	}

	// The ts.net path still works alongside BYO entries.
	got, err = e.resolveCertDomain(b, tsNetDomain)
	if err != nil {
		t.Fatalf("resolveCertDomain(%q): %v", tsNetDomain, err)
	}
	if got != tsNetDomain {
		t.Errorf("resolveCertDomain(%q) = %q, want %q", tsNetDomain, got, tsNetDomain)
	}
}

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
	mustMakePair := func(template *x509.Certificate) *ipnlocal.TLSCertKeyPair {
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

		return &ipnlocal.TLSCertKeyPair{
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
			name:      "should-renew",
			notBefore: now.AddDate(0, 0, -89),
			lifetime:  90 * 24 * time.Hour,
			want:      true,
		},
		{
			name:      "short-lived-renewal",
			notBefore: now.AddDate(0, 0, -7),
			lifetime:  10 * 24 * time.Hour,
			want:      true,
		},
		{
			name:      "no-renew",
			notBefore: now.AddDate(0, 0, -59), // 59 days ago == not 2/3rds of the way through 90 days yet
			lifetime:  90 * 24 * time.Hour,
			want:      false,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := domainRenewalTimeByExpiry(mustMakePair(&x509.Certificate{
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
			e := &extension{}
			ac, err := e.acmeClient(certStateStore{StateStore: new(mem.Store)})
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
	b := ipnlocaltest.NewBackend(t)
	b.SetVarRoot(t.TempDir())
	e := extOf(t, b)

	// Set up netmap with CertDomains so resolveCertDomain works.
	b.ForTest().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{}).View(),
		DNS: tailcfg.DNSConfig{
			CertDomains: []string{testDomain},
		},
	})

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

			tstest.AssertNotParallel(t)
			if tt.readOnlyMode {
				envknob.Setenv("TS_CERT_SHARE_MODE", "ro")
			} else {
				envknob.Setenv("TS_CERT_SHARE_MODE", "")
			}

			os.RemoveAll(certDirPath)
			if tt.storeCerts {
				os.MkdirAll(certDirPath, 0755)
				if err := os.WriteFile(filepath.Join(certDirPath, "example.com.crt"),
					must.Get(certTestFS.ReadFile("testdata/example.com.pem")), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(certDirPath, "example.com.key"),
					must.Get(certTestFS.ReadFile("testdata/example.com-key.pem")), 0644); err != nil {
					t.Fatal(err)
				}
			}

			b.ForTest().SetClock(tstest.NewClock(tstest.ClockOpts{Start: tt.now}))

			// Set to true if getCertPEM is called. GetCertPEM can be called in
			// a goroutine for async renewal or in the main goroutine if
			// issuance is required to obtain valid TLS credentials.
			getCertPemWasCalled := false
			orig := getCertPEM
			getCertPEM = func(ctx context.Context, e *extension, b *ipnlocal.LocalBackend, cs certStore, logf logger.Logf, traceACME func(any), domain string, now time.Time, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
				getCertPemWasCalled = true
				return nil, nil
			}
			t.Cleanup(func() { getCertPEM = orig })
			prevGo := e.goroutinesStarted.Load()
			_, err = b.GetCertPEMWithValidity(context.Background(), testDomain, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("b.GetCertPemWithValidity got err %v, wants error: '%v'", err, tt.wantErr)
			}
			// GetCertPEMWithValidity spawns one tracked goroutine (via
			// extension.Go) iff it kicked off async renewal.
			gotAsyncRenewal := e.goroutinesStarted.Load()-prevGo != 0
			if gotAsyncRenewal {
				done := make(chan struct{})
				go func() { e.wg.Wait(); close(done) }()
				select {
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for async renewal goroutine to finish")
				case <-done:
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

func TestCertPendingWarnable(t *testing.T) {
	b := ipnlocaltest.NewBackend(t)
	e := extOf(t, b)

	// currentWarning returns the pending warning's rendered text and
	// domain-list arg, or "", "" if the warnable is currently healthy.
	currentWarning := func() (text, domains string) {
		ws, ok := b.HealthTracker().CurrentState().Warnings[tsconst.HealthWarnableTLSCertPending]
		if !ok {
			return "", ""
		}
		return ws.Text, ws.Args[health.ArgDomains]
	}

	if b.HealthTracker().IsUnhealthy(certPendingWarnable) {
		t.Fatal("warnable unexpectedly unhealthy before any setCertPending")
	}

	e.setCertPending(b, "a.example.com", true)
	if !b.HealthTracker().IsUnhealthy(certPendingWarnable) {
		t.Fatal("warnable not unhealthy after first setCertPending")
	}
	if text, domains := currentWarning(); domains != "a.example.com" ||
		text != "Fetching TLS certificate via ACME for: a.example.com" {
		t.Errorf("after first setCertPending: text=%q domains=%q", text, domains)
	}

	e.setCertPending(b, "b.example.com", true)
	if !b.HealthTracker().IsUnhealthy(certPendingWarnable) {
		t.Fatal("warnable not unhealthy after second setCertPending")
	}
	if text, domains := currentWarning(); domains != "a.example.com, b.example.com" ||
		text != "Fetching TLS certificate via ACME for: a.example.com, b.example.com" {
		t.Errorf("after second setCertPending: text=%q domains=%q", text, domains)
	}

	e.setCertPending(b, "a.example.com", false)
	if !b.HealthTracker().IsUnhealthy(certPendingWarnable) {
		t.Fatal("warnable cleared too early; one domain still pending")
	}
	if text, domains := currentWarning(); domains != "b.example.com" ||
		text != "Fetching TLS certificate via ACME for: b.example.com" {
		t.Errorf("after clearing a.example.com: text=%q domains=%q", text, domains)
	}

	e.setCertPending(b, "b.example.com", false)
	if b.HealthTracker().IsUnhealthy(certPendingWarnable) {
		t.Fatal("warnable still unhealthy after clearing all domains")
	}
	if text, domains := currentWarning(); text != "" || domains != "" {
		t.Errorf("after clearing all domains: text=%q domains=%q", text, domains)
	}
}

func TestServeConfigUsesACMECerts(t *testing.T) {
	tests := []struct {
		name string
		sc   *ipn.ServeConfig
		want bool
	}{
		{"nil", nil, false},
		{"empty", &ipn.ServeConfig{}, false},
		{
			name: "background_web",
			sc: &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"node.ts.net:443": {},
				},
			},
			want: true,
		},
		{
			name: "tcp_forward_no_tls",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {TCPForward: "127.0.0.1:443"}},
			},
			want: false,
		},
		{
			name: "tls_terminated_tcp",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {TCPForward: "127.0.0.1:443", TerminateTLS: "node.ts.net"},
				},
			},
			want: true,
		},
		{
			name: "service_tls_terminated_tcp",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:web": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {TCPForward: "127.0.0.1:443", TerminateTLS: "web.svc.ts.net"},
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v ipn.ServeConfigView
			if tt.sc != nil {
				v = tt.sc.View()
			}
			if got := serveConfigUsesACMECerts(v); got != tt.want {
				t.Errorf("serveConfigUsesACMECerts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefreshApplicableCerts(t *testing.T) {
	const (
		certDomain = "node1.example.com"
		byoDomain  = "byo.example.org"
	)
	b := ipnlocaltest.NewBackend(t)
	b.SetVarRoot(t.TempDir())
	e := extOf(t, b)

	b.ForTest().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{}).View(),
		DNS: tailcfg.DNSConfig{
			CertDomains: []string{certDomain},
		},
	})
	b.ForTest().SetServeConfig((&ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			ipn.HostPort(certDomain + ":443"): {},
			ipn.HostPort(byoDomain + ":443"):  {},
			// Not in CertDomains and no Funnel entry; must be filtered out.
			ipn.HostPort("not-ours.other.tld:443"): {},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			ipn.HostPort(byoDomain + ":443"): true,
		},
	}).View())

	gotCh := make(chan string, 4)
	b.ForTest().ConfigureCerts(func(host string) (*ipnlocal.TLSCertKeyPair, error) {
		gotCh <- host
		return &ipnlocal.TLSCertKeyPair{}, nil
	})

	e.refreshApplicableCerts(context.Background(), b)

	want := set.Of(certDomain, byoDomain)
	got := set.Set[string]{}
	for got.Len() < want.Len() {
		select {
		case h := <-gotCh:
			got.Add(h)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for refresh workers; got %v, want %v", got, want)
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("got fetches %v, want %v", got, want)
	}
	select {
	case h := <-gotCh:
		t.Errorf("unexpected extra fetch for %q", h)
	default:
	}
}

// TestLockDomain_SameDomainReturnsSameMutex verifies the repeat
// calls for the same domain return the same mutex, and different
// domains get distinct mutexes.
func TestLockDomain_SameDomainReturnsSameMutex(t *testing.T) {
	const domA, domB = "a.example.com", "b.example.com"
	e := &extension{}
	a1 := e.lockDomain(domA)
	a2 := e.lockDomain(domA)
	b := e.lockDomain(domB)
	if a1 != a2 {
		t.Errorf("lockDomain(%q) second call = %p, want %p", domA, a2, a1)
	}
	if a1 == b {
		t.Errorf("lockDomain(%q) = lockDomain(%q) = %p, want different", domA, domB, a1)
	}
}

// TestLockDomain_PerDomainConcurrency verifies a lock on one
// domain doesn't block another, and the same domain blocks while held
// and is acquireable again after release.
func TestLockDomain_PerDomainConcurrency(t *testing.T) {
	const domA, domB = "a.example.com", "b.example.com"
	e := &extension{}

	aLock := e.lockDomain(domA)
	aLock.Lock()

	bLock := e.lockDomain(domB)
	if !bLock.TryLock() {
		t.Errorf("lockDomain(%q).TryLock() = false while %q held, want true", domB, domA)
	} else {
		bLock.Unlock()
	}

	if aLock.TryLock() {
		t.Errorf("lockDomain(%q).TryLock() = true while held, want false", domA)
	}

	aLock.Unlock()

	if !aLock.TryLock() {
		t.Errorf("lockDomain(%q).TryLock() = false after release, want true", domA)
	}
	aLock.Unlock()
}

// TestAcmeKey_ConcurrentFirstCall verifies that N goroutines racing on
// an empty store all return the key that ends up persisted.
func TestAcmeKey_ConcurrentFirstCall(t *testing.T) {
	e := &extension{}
	cs := certStateStore{StateStore: new(mem.Store)}

	const n = 16
	type result struct {
		key crypto.Signer
		err error
	}
	results := make(chan result, n)
	var start sync.WaitGroup
	start.Add(1)
	for range n {
		go func() {
			start.Wait()
			k, err := e.acmeKey(cs)
			results <- result{k, err}
		}()
	}
	start.Done()

	var keys []crypto.Signer
	for range n {
		r := <-results
		if r.err != nil {
			t.Fatalf("acmeKey: %v", r.err)
		}
		keys = append(keys, r.key)
	}

	persisted, err := cs.ACMEKey()
	if err != nil {
		t.Fatalf("cs.ACMEKey after race: %v", err)
	}
	block, _ := pem.Decode(persisted)
	if block == nil {
		t.Fatal("no PEM block in persisted ACME key")
	}
	want, err := parsePrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing persisted key: %v", err)
	}
	wantPub, err := x509.MarshalPKIXPublicKey(want.Public())
	if err != nil {
		t.Fatalf("marshaling persisted pubkey: %v", err)
	}
	for i, k := range keys {
		gotPub, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			t.Fatalf("marshaling returned key %d: %v", i, err)
		}
		if !bytes.Equal(gotPub, wantPub) {
			t.Errorf("goroutine %d returned a different account key than the persisted one", i)
		}
	}
}
