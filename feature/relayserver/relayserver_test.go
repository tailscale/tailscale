// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package relayserver

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

func Test_extension_profileStateChanged(t *testing.T) {
	prefsWithPortOne := ipn.Prefs{RelayServerPort: ptr.To(1)}
	prefsWithNilPort := ipn.Prefs{RelayServerPort: nil}
	prefsWithPortOneRelayEndpoints := ipn.Prefs{
		RelayServerPort:            ptr.To(1),
		RelayServerStaticEndpoints: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7777")},
	}

	type fields struct {
		port            *int
		staticEndpoints views.Slice[netip.AddrPort]
		rs              relayServer
	}
	type args struct {
		prefs    ipn.PrefsView
		sameNode bool
	}
	tests := []struct {
		name                        string
		fields                      fields
		args                        args
		wantPort                    *int
		wantRelayServerFieldNonNil  bool
		wantRelayServerFieldMutated bool
		wantEndpoints               []netip.AddrPort
	}{
		{
			name: "no changes non-nil port previously running",
			fields: fields{
				port: ptr.To(1),
				rs:   mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: false,
		},
		{
			name: "set addr ports unchanged port previously running",
			fields: fields{
				port: ptr.To(1),
				rs:   mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithPortOneRelayEndpoints.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: false,
			wantEndpoints:               prefsWithPortOneRelayEndpoints.RelayServerStaticEndpoints,
		},
		{
			name: "set addr ports not previously running",
			fields: fields{
				port: nil,
				rs:   nil,
			},
			args: args{
				prefs:    prefsWithPortOneRelayEndpoints.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
			wantEndpoints:               prefsWithPortOneRelayEndpoints.RelayServerStaticEndpoints,
		},
		{
			name: "clear addr ports unchanged port previously running",
			fields: fields{
				port:            ptr.To(1),
				staticEndpoints: views.SliceOf(prefsWithPortOneRelayEndpoints.RelayServerStaticEndpoints),
				rs:              mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: false,
			wantEndpoints:               nil,
		},
		{
			name: "prefs port nil",
			fields: fields{
				port: ptr.To(1),
			},
			args: args{
				prefs:    prefsWithNilPort.View(),
				sameNode: true,
			},
			wantPort:                    nil,
			wantRelayServerFieldNonNil:  false,
			wantRelayServerFieldMutated: false,
		},
		{
			name: "prefs port nil previously running",
			fields: fields{
				port: ptr.To(1),
				rs:   mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithNilPort.View(),
				sameNode: true,
			},
			wantPort:                    nil,
			wantRelayServerFieldNonNil:  false,
			wantRelayServerFieldMutated: true,
		},
		{
			name: "prefs port changed",
			fields: fields{
				port: ptr.To(2),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
		},
		{
			name: "prefs port changed previously running",
			fields: fields{
				port: ptr.To(2),
				rs:   mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
		},
		{
			name: "sameNode false",
			fields: fields{
				port: ptr.To(1),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: false,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
		},
		{
			name: "sameNode false previously running",
			fields: fields{
				port: ptr.To(1),
				rs:   mockRelayServerNotZeroVal(),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: false,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
		},
		{
			name: "prefs port non-nil extension port nil",
			fields: fields{
				port: nil,
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: false,
			},
			wantPort:                    ptr.To(1),
			wantRelayServerFieldNonNil:  true,
			wantRelayServerFieldMutated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := tsd.NewSystem()
			ipne, err := newExtension(logger.Discard, mockSafeBackend{sys})
			if err != nil {
				t.Fatal(err)
			}
			e := ipne.(*extension)
			e.newServerFn = func(logf logger.Logf, port int, onlyStaticAddrPorts bool) (relayServer, error) {
				return &mockRelayServer{}, nil
			}
			e.port = tt.fields.port
			e.staticEndpoints = tt.fields.staticEndpoints
			e.rs = tt.fields.rs
			defer e.Shutdown()
			e.profileStateChanged(ipn.LoginProfileView{}, tt.args.prefs, tt.args.sameNode)
			if tt.wantRelayServerFieldNonNil != (e.rs != nil) {
				t.Errorf("wantRelayServerFieldNonNil: %v != (e.rs != nil): %v", tt.wantRelayServerFieldNonNil, e.rs != nil)
			}
			if (tt.wantPort == nil) != (e.port == nil) {
				t.Errorf("(tt.wantPort == nil): %v != (e.port == nil): %v", tt.wantPort == nil, e.port == nil)
			} else if tt.wantPort != nil && *tt.wantPort != *e.port {
				t.Errorf("wantPort: %d != *e.port: %d", *tt.wantPort, *e.port)
			}
			if tt.wantRelayServerFieldMutated != !reflect.DeepEqual(tt.fields.rs, e.rs) {
				t.Errorf("wantRelayServerFieldMutated: %v != !reflect.DeepEqual(tt.fields.rs, e.rs): %v", tt.wantRelayServerFieldMutated, !reflect.DeepEqual(tt.fields.rs, e.rs))
			}
			if !slices.Equal(tt.wantEndpoints, e.staticEndpoints.AsSlice()) {
				t.Errorf("wantEndpoints: %v != %v", tt.wantEndpoints, e.staticEndpoints.AsSlice())
			}
			if e.rs != nil && !slices.Equal(tt.wantEndpoints, e.rs.(*mockRelayServer).addrPorts.AsSlice()) {
				t.Errorf("wantEndpoints: %v != %v", tt.wantEndpoints, e.rs.(*mockRelayServer).addrPorts.AsSlice())
			}
		})
	}
}

func mockRelayServerNotZeroVal() *mockRelayServer {
	return &mockRelayServer{set: true}
}

type mockRelayServer struct {
	set       bool
	addrPorts views.Slice[netip.AddrPort]
}

func (m *mockRelayServer) Close() error { return nil }
func (m *mockRelayServer) AllocateEndpoint(_, _ key.DiscoPublic) (endpoint.ServerEndpoint, error) {
	return endpoint.ServerEndpoint{}, errors.New("not implemented")
}
func (m *mockRelayServer) GetSessions() []status.ServerSession { return nil }
func (m *mockRelayServer) SetDERPMapView(tailcfg.DERPMapView)  { return }
func (m *mockRelayServer) SetStaticAddrPorts(aps views.Slice[netip.AddrPort]) {
	m.addrPorts = aps
}

type mockSafeBackend struct {
	sys *tsd.System
}

func (m mockSafeBackend) Sys() *tsd.System       { return m.sys }
func (mockSafeBackend) Clock() tstime.Clock      { return nil }
func (mockSafeBackend) TailscaleVarRoot() string { return "" }

func Test_extension_handleRelayServerLifetimeLocked(t *testing.T) {
	tests := []struct {
		name                          string
		shutdown                      bool
		port                          *int
		rs                            relayServer
		hasNodeAttrDisableRelayServer bool
		wantRelayServerFieldNonNil    bool
		wantRelayServerFieldMutated   bool
	}{
		{
			name:                          "want running",
			shutdown:                      false,
			port:                          ptr.To(1),
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    true,
			wantRelayServerFieldMutated:   true,
		},
		{
			name:                          "want running previously running",
			shutdown:                      false,
			port:                          ptr.To(1),
			rs:                            mockRelayServerNotZeroVal(),
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    true,
			wantRelayServerFieldMutated:   false,
		},
		{
			name:                          "shutdown true",
			shutdown:                      true,
			port:                          ptr.To(1),
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   false,
		},
		{
			name:                          "shutdown true previously running",
			shutdown:                      true,
			port:                          ptr.To(1),
			rs:                            mockRelayServerNotZeroVal(),
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   true,
		},
		{
			name:                          "port nil",
			shutdown:                      false,
			port:                          nil,
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   false,
		},
		{
			name:                          "port nil previously running",
			shutdown:                      false,
			port:                          nil,
			rs:                            mockRelayServerNotZeroVal(),
			hasNodeAttrDisableRelayServer: false,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   true,
		},
		{
			name:                          "hasNodeAttrDisableRelayServer true",
			shutdown:                      false,
			port:                          nil,
			hasNodeAttrDisableRelayServer: true,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   false,
		},
		{
			name:                          "hasNodeAttrDisableRelayServer true previously running",
			shutdown:                      false,
			port:                          nil,
			rs:                            mockRelayServerNotZeroVal(),
			hasNodeAttrDisableRelayServer: true,
			wantRelayServerFieldNonNil:    false,
			wantRelayServerFieldMutated:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := tsd.NewSystem()
			ipne, err := newExtension(logger.Discard, mockSafeBackend{sys})
			if err != nil {
				t.Fatal(err)
			}
			e := ipne.(*extension)
			e.newServerFn = func(logf logger.Logf, port int, onlyStaticAddrPorts bool) (relayServer, error) {
				return &mockRelayServer{}, nil
			}
			e.shutdown = tt.shutdown
			e.port = tt.port
			e.rs = tt.rs
			e.hasNodeAttrDisableRelayServer = tt.hasNodeAttrDisableRelayServer
			e.handleRelayServerLifetimeLocked()
			defer e.Shutdown()
			if tt.wantRelayServerFieldNonNil != (e.rs != nil) {
				t.Errorf("wantRelayServerFieldNonNil: %v != (e.rs != nil): %v", tt.wantRelayServerFieldNonNil, e.rs != nil)
			}
			if tt.wantRelayServerFieldMutated != !reflect.DeepEqual(tt.rs, e.rs) {
				t.Errorf("wantRelayServerFieldMutated: %v != !reflect.DeepEqual(tt.rs, e.rs): %v", tt.wantRelayServerFieldMutated, !reflect.DeepEqual(tt.rs, e.rs))
			}
		})
	}
}
