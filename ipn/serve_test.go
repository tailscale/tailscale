// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	portAttr := "https://tailscale.com/cap/funnel-ports?ports=443,8080-8090,8443,"
	tests := []struct {
		port    uint16
		caps    []string
		wantErr bool
	}{
		{443, []string{portAttr}, true}, // No "funnel" attribute
		{443, []string{portAttr, tailcfg.CapabilityWarnFunnelNoInvite}, true},
		{443, []string{portAttr, tailcfg.CapabilityWarnFunnelNoHTTPS}, true},
		{443, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8443, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8321, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
		{8083, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8091, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
		{3000, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
	}
	for _, tt := range tests {
		err := CheckFunnelAccess(tt.port, tt.caps)
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
