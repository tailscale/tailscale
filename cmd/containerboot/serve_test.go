// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
)

func TestUpdateServeConfig(t *testing.T) {
	tests := []struct {
		name       string
		sc         *ipn.ServeConfig
		certDomain string
		wantCall   bool
	}{
		{
			name: "no_https_no_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {HTTP: true},
				},
			},
			certDomain: kubetypes.ValueNoHTTPS, // tailnet has HTTPS disabled
			wantCall:   true,                   // should set serve config as it doesn't have HTTPS endpoints
		},
		{
			name: "https_with_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"${TS_CERT_DOMAIN}:443": {
						Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://10.0.1.100:8080"},
						},
					},
				},
			},
			certDomain: "test-node.tailnet.ts.net",
			wantCall:   true,
		},
		{
			name: "https_without_cert_domain",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
			},
			certDomain: kubetypes.ValueNoHTTPS,
			wantCall:   false, // incorrect configuration- should not set serve config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeLC := &fakeLocalClient{}
			err := updateServeConfig(context.Background(), tt.sc, tt.certDomain, fakeLC)
			if err != nil {
				t.Errorf("updateServeConfig() error = %v", err)
			}
			if fakeLC.setServeCalled != tt.wantCall {
				t.Errorf("SetServeConfig() called = %v, want %v", fakeLC.setServeCalled, tt.wantCall)
			}
		})
	}
}

func TestReadServeConfig(t *testing.T) {
	tests := []struct {
		name       string
		gotSC      string
		certDomain string
		wantSC     *ipn.ServeConfig
		wantErr    bool
	}{
		{
			name: "empty_file",
		},
		{
			name: "valid_config_with_cert_domain_placeholder",
			gotSC: `{
				"TCP": {
					"443": {
						"HTTPS": true
					}
				},
				"Web": {
					"${TS_CERT_DOMAIN}:443": {
					"Handlers": {
						"/api": {
							"Proxy": "https://10.2.3.4/api"
						}}}}}`,
			certDomain: "example.com",
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort("example.com:443"): {
						Handlers: map[string]*ipn.HTTPHandler{
							"/api": {
								Proxy: "https://10.2.3.4/api",
							},
						},
					},
				},
			},
		},
		{
			name: "valid_config_for_http_proxy",
			gotSC: `{
				"TCP": {
					"80": {
						"HTTP": true
					}
				}}`,
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {
						HTTP: true,
					},
				},
			},
		},
		{
			name: "config_without_cert_domain",
			gotSC: `{
				"TCP": {
					"443": {
						"HTTPS": true
					}
				},
				"Web": {
					"localhost:443": {
					"Handlers": {
						"/api": {
							"Proxy": "https://10.2.3.4/api"
						}}}}}`,
			certDomain: "",
			wantErr:    false,
			wantSC: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					ipn.HostPort("localhost:443"): {
						Handlers: map[string]*ipn.HTTPHandler{
							"/api": {
								Proxy: "https://10.2.3.4/api",
							},
						},
					},
				},
			},
		},
		{
			name:    "invalid_json",
			gotSC:   "invalid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "serve-config.json")
			if err := os.WriteFile(path, []byte(tt.gotSC), 0644); err != nil {
				t.Fatal(err)
			}

			got, err := readServeConfig(path, tt.certDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("readServeConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.wantSC) {
				t.Errorf("readServeConfig() diff (-got +want):\n%s", cmp.Diff(got, tt.wantSC))
			}
		})
	}
}

type fakeLocalClient struct {
	*local.Client
	setServeCalled bool
}

func (m *fakeLocalClient) SetServeConfig(ctx context.Context, cfg *ipn.ServeConfig) error {
	m.setServeCalled = true
	return nil
}

func (m *fakeLocalClient) CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	return nil, nil, nil
}

func TestHasHTTPSEndpoint(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ipn.ServeConfig
		want bool
	}{
		{
			name: "nil_config",
			cfg:  nil,
			want: false,
		},
		{
			name: "empty_config",
			cfg:  &ipn.ServeConfig{},
			want: false,
		},
		{
			name: "no_https_endpoints",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {
						HTTPS: false,
					},
				},
			},
			want: false,
		},
		{
			name: "has_https_endpoint",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
			},
			want: true,
		},
		{
			name: "mixed_endpoints",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80:  {HTTPS: false},
					443: {HTTPS: true},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasHTTPSEndpoint(tt.cfg)
			if got != tt.want {
				t.Errorf("hasHTTPSEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
