// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package relayserver

import (
	"errors"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

type fakeRelayServer struct{}

func (f *fakeRelayServer) Close() error { return nil }

func (f *fakeRelayServer) AllocateEndpoint(_, _ key.DiscoPublic) (endpoint.ServerEndpoint, error) {
	return endpoint.ServerEndpoint{}, errors.New("fake relay server")
}

func Test_extension_profileStateChanged(t *testing.T) {
	prefsWithPortOne := ipn.Prefs{RelayServerPort: ptr.To(1)}
	prefsWithNilPort := ipn.Prefs{RelayServerPort: nil}

	type fields struct {
		server relayServer
		port   *int
	}
	type args struct {
		prefs    ipn.PrefsView
		sameNode bool
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantPort      *int
		wantNilServer bool
	}{
		{
			name: "no changes non-nil server",
			fields: fields{
				server: &fakeRelayServer{},
				port:   ptr.To(1),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:      ptr.To(1),
			wantNilServer: false,
		},
		{
			name: "prefs port nil",
			fields: fields{
				server: &fakeRelayServer{},
				port:   ptr.To(1),
			},
			args: args{
				prefs:    prefsWithNilPort.View(),
				sameNode: true,
			},
			wantPort:      nil,
			wantNilServer: true,
		},
		{
			name: "prefs port changed",
			fields: fields{
				server: &fakeRelayServer{},
				port:   ptr.To(2),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:      ptr.To(1),
			wantNilServer: true,
		},
		{
			name: "sameNode false",
			fields: fields{
				server: &fakeRelayServer{},
				port:   ptr.To(1),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: false,
			},
			wantPort:      ptr.To(1),
			wantNilServer: true,
		},
		{
			name: "prefs port non-nil extension port nil",
			fields: fields{
				server: nil,
				port:   nil,
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: false,
			},
			wantPort:      ptr.To(1),
			wantNilServer: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &extension{
				port:   tt.fields.port,
				server: tt.fields.server,
			}
			e.profileStateChanged(ipn.LoginProfileView{}, tt.args.prefs, tt.args.sameNode)
			if tt.wantNilServer != (e.server == nil) {
				t.Errorf("wantNilServer: %v != (e.server == nil): %v", tt.wantNilServer, e.server == nil)
			}
			if (tt.wantPort == nil) != (e.port == nil) {
				t.Errorf("(tt.wantPort == nil): %v != (e.port == nil): %v", tt.wantPort == nil, e.port == nil)
			} else if tt.wantPort != nil && *tt.wantPort != *e.port {
				t.Errorf("wantPort: %d != *e.port: %d", *tt.wantPort, *e.port)
			}
		})
	}
}
