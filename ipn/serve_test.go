// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	caps := func(c ...tailcfg.NodeCapability) []tailcfg.NodeCapability { return c }
	const portAttr tailcfg.NodeCapability = "https://tailscale.com/cap/funnel-ports?ports=443,8080-8090,8443,"
	tests := []struct {
		port    uint16
		caps    []tailcfg.NodeCapability
		wantErr bool
	}{
		{443, caps(portAttr), true}, // No "funnel" attribute
		{443, caps(portAttr, tailcfg.NodeAttrFunnel), true},
		{443, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8443, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8321, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
		{8083, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8091, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
		{3000, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
	}
	for _, tt := range tests {
		cm := tailcfg.NodeCapMap{}
		for _, c := range tt.caps {
			cm[c] = nil
		}
		err := CheckFunnelAccess(tt.port, &ipnstate.PeerStatus{CapMap: cm})
		switch {
		case err != nil && tt.wantErr,
			err == nil && !tt.wantErr:
			continue
		case tt.wantErr:
			t.Fatalf("got no error, want error")
		case !tt.wantErr:
			t.Fatalf("got error %v, want no error", err)
		}
	}
}

func TestHasPathHandler(t *testing.T) {
	tests := []struct {
		name string
		cfg  ServeConfig
		want bool
	}{
		{
			name: "empty-config",
			cfg:  ServeConfig{},
			want: false,
		},
		{
			name: "with-bg-path-handler",
			cfg: ServeConfig{
				TCP: map[uint16]*TCPPortHandler{80: {HTTP: true}},
				Web: map[HostPort]*WebServerConfig{
					"foo.test.ts.net:80": {Handlers: map[string]*HTTPHandler{
						"/": {Path: "/tmp"},
					}},
				},
			},
			want: true,
		},
		{
			name: "with-fg-path-handler",
			cfg: ServeConfig{
				TCP: map[uint16]*TCPPortHandler{
					443: {HTTPS: true},
				},
				Foreground: map[string]*ServeConfig{
					"abc123": {
						TCP: map[uint16]*TCPPortHandler{80: {HTTP: true}},
						Web: map[HostPort]*WebServerConfig{
							"foo.test.ts.net:80": {Handlers: map[string]*HTTPHandler{
								"/": {Path: "/tmp"},
							}},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "with-no-bg-path-handler",
			cfg: ServeConfig{
				TCP: map[uint16]*TCPPortHandler{443: {HTTPS: true}},
				Web: map[HostPort]*WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
				AllowFunnel: map[HostPort]bool{"foo.test.ts.net:443": true},
			},
			want: false,
		},
		{
			name: "with-no-fg-path-handler",
			cfg: ServeConfig{
				Foreground: map[string]*ServeConfig{
					"abc123": {
						TCP: map[uint16]*TCPPortHandler{443: {HTTPS: true}},
						Web: map[HostPort]*WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*HTTPHandler{
								"/": {Proxy: "http://127.0.0.1:3000"},
							}},
						},
						AllowFunnel: map[HostPort]bool{"foo.test.ts.net:443": true},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.HasPathHandler()
			if tt.want != got {
				t.Errorf("HasPathHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandProxyTargetDev(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		defaultScheme    string
		supportedSchemes []string
		expected         string
		wantErr          bool
	}{
		{name: "port-only", input: "8080", expected: "http://127.0.0.1:8080"},
		{name: "hostname+port", input: "localhost:8080", expected: "http://localhost:8080"},
		{name: "no-change", input: "http://127.0.0.1:8080", expected: "http://127.0.0.1:8080"},
		{name: "include-path", input: "http://127.0.0.1:8080/foo", expected: "http://127.0.0.1:8080/foo"},
		{name: "https-scheme", input: "https://localhost:8080", expected: "https://localhost:8080"},
		{name: "https+insecure-scheme", input: "https+insecure://localhost:8080", expected: "https+insecure://localhost:8080"},
		{name: "change-default-scheme", input: "localhost:8080", defaultScheme: "https", expected: "https://localhost:8080"},
		{name: "change-supported-schemes", input: "localhost:8080", defaultScheme: "tcp", supportedSchemes: []string{"tcp"}, expected: "tcp://localhost:8080"},

		// errors
		{name: "invalid-port", input: "localhost:9999999", wantErr: true},
		{name: "unsupported-scheme", input: "ftp://localhost:8080", expected: "", wantErr: true},
		{name: "not-localhost", input: "https://tailscale.com:8080", expected: "", wantErr: true},
		{name: "empty-input", input: "", expected: "", wantErr: true},
	}

	for _, tt := range tests {
		defaultScheme := "http"
		supportedSchemes := []string{"http", "https", "https+insecure"}

		if tt.supportedSchemes != nil {
			supportedSchemes = tt.supportedSchemes
		}
		if tt.defaultScheme != "" {
			defaultScheme = tt.defaultScheme
		}

		t.Run(tt.name, func(t *testing.T) {
			actual, err := ExpandProxyTargetValue(tt.input, supportedSchemes, defaultScheme)

			if tt.wantErr == true && err == nil {
				t.Errorf("Expected an error but got none")
				return
			}

			if tt.wantErr == false && err != nil {
				t.Errorf("Got an error, but didn't expect one: %v", err)
				return
			}

			if actual != tt.expected {
				t.Errorf("Got: %q; expected: %q", actual, tt.expected)
			}
		})
	}
}

func TestIsFunnelOn(t *testing.T) {
	tests := []struct {
		name string
		sc   *ServeConfig
		want bool
	}{
		{
			name: "nil_config",
		},
		{
			name: "empty_config",
			sc:   &ServeConfig{},
		},
		{
			name: "funnel_enabled_in_background",
			sc: &ServeConfig{
				AllowFunnel: map[HostPort]bool{
					"tailnet.xyz:443": true,
				},
			},
			want: true,
		},
		{
			name: "funnel_disabled_in_background",
			sc: &ServeConfig{
				AllowFunnel: map[HostPort]bool{
					"tailnet.xyz:443": false,
				},
			},
		},
		{
			name: "funnel_enabled_in_foreground",
			sc: &ServeConfig{
				Foreground: map[string]*ServeConfig{
					"abc123": {
						AllowFunnel: map[HostPort]bool{
							"tailnet.xyz:443": true,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "funnel_disabled_in_both",
			sc: &ServeConfig{
				AllowFunnel: map[HostPort]bool{
					"tailnet.xyz:443": false,
				},
				Foreground: map[string]*ServeConfig{
					"abc123": {
						AllowFunnel: map[HostPort]bool{
							"tailnet.xyz:8443": false,
						},
					},
				},
			},
		},
		{
			name: "funnel_enabled_in_both",
			sc: &ServeConfig{
				AllowFunnel: map[HostPort]bool{
					"tailnet.xyz:443": true,
				},
				Foreground: map[string]*ServeConfig{
					"abc123": {
						AllowFunnel: map[HostPort]bool{
							"tailnet.xyz:8443": true,
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sc.IsFunnelOn(); got != tt.want {
				t.Errorf("ServeConfig.IsFunnelOn() = %v, want %v", got, tt.want)
			}
		})
	}
}
