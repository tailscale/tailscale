// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package relayserver

import (
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
	"tailscale.com/util/eventbus"
)

func Test_extension_profileStateChanged(t *testing.T) {
	prefsWithPortOne := ipn.Prefs{RelayServerPort: ptr.To(1)}
	prefsWithNilPort := ipn.Prefs{RelayServerPort: nil}

	type fields struct {
		port *int
	}
	type args struct {
		prefs    ipn.PrefsView
		sameNode bool
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantPort       *int
		wantBusRunning bool
	}{
		{
			name: "no changes non-nil port",
			fields: fields{
				port: ptr.To(1),
			},
			args: args{
				prefs:    prefsWithPortOne.View(),
				sameNode: true,
			},
			wantPort:       ptr.To(1),
			wantBusRunning: true,
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
			wantPort:       nil,
			wantBusRunning: false,
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
			wantPort:       ptr.To(1),
			wantBusRunning: true,
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
			wantPort:       ptr.To(1),
			wantBusRunning: true,
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
			wantPort:       ptr.To(1),
			wantBusRunning: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := tsd.NewSystem()
			bus := sys.Bus.Get()
			e := &extension{
				logf: logger.Discard,
				port: tt.fields.port,
				bus:  bus,
			}
			defer e.disconnectFromBusLocked()
			e.profileStateChanged(ipn.LoginProfileView{}, tt.args.prefs, tt.args.sameNode)
			if tt.wantBusRunning != (e.eventSubs != nil) {
				t.Errorf("wantBusRunning: %v != (e.eventSubs != nil): %v", tt.wantBusRunning, e.eventSubs != nil)
			}
			if (tt.wantPort == nil) != (e.port == nil) {
				t.Errorf("(tt.wantPort == nil): %v != (e.port == nil): %v", tt.wantPort == nil, e.port == nil)
			} else if tt.wantPort != nil && *tt.wantPort != *e.port {
				t.Errorf("wantPort: %d != *e.port: %d", *tt.wantPort, *e.port)
			}
		})
	}
}

func Test_extension_handleBusLifetimeLocked(t *testing.T) {
	tests := []struct {
		name                          string
		shutdown                      bool
		port                          *int
		eventSubs                     *eventbus.Monitor
		hasNodeAttrDisableRelayServer bool
		wantBusRunning                bool
	}{
		{
			name:                          "want running",
			shutdown:                      false,
			port:                          ptr.To(1),
			hasNodeAttrDisableRelayServer: false,
			wantBusRunning:                true,
		},
		{
			name:                          "shutdown true",
			shutdown:                      true,
			port:                          ptr.To(1),
			hasNodeAttrDisableRelayServer: false,
			wantBusRunning:                false,
		},
		{
			name:                          "port nil",
			shutdown:                      false,
			port:                          nil,
			hasNodeAttrDisableRelayServer: false,
			wantBusRunning:                false,
		},
		{
			name:                          "hasNodeAttrDisableRelayServer true",
			shutdown:                      false,
			port:                          nil,
			hasNodeAttrDisableRelayServer: true,
			wantBusRunning:                false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &extension{
				logf:                          logger.Discard,
				bus:                           eventbus.New(),
				shutdown:                      tt.shutdown,
				port:                          tt.port,
				eventSubs:                     tt.eventSubs,
				hasNodeAttrDisableRelayServer: tt.hasNodeAttrDisableRelayServer,
			}
			e.handleBusLifetimeLocked()
			defer e.disconnectFromBusLocked()
			if tt.wantBusRunning != (e.eventSubs != nil) {
				t.Errorf("wantBusRunning: %v != (e.eventSubs != nil): %v", tt.wantBusRunning, e.eventSubs != nil)
			}
		})
	}
}
