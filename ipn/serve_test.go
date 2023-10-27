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
