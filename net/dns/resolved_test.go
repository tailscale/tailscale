// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_resolved

package dns

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestResolvedManagerNameOwnerChangedSignal(t *testing.T) {
	m := &resolvedManager{logf: t.Logf}
	tests := []struct {
		name   string
		signal *dbus.Signal
		want   bool
	}{
		{
			name: "nil-signal",
		},
		{
			name:   "empty-body",
			signal: nameOwnerChangedSignal(),
		},
		{
			name:   "short-body",
			signal: nameOwnerChangedSignal(dbusResolvedObject, "previous owner"),
		},
		{
			name:   "long-body",
			signal: nameOwnerChangedSignal(dbusResolvedObject, "previous owner", "new owner", "extra"),
		},
		{
			name:   "wrong-new-owner-type",
			signal: nameOwnerChangedSignal(dbusResolvedObject, "previous owner", 123),
		},
		{
			name: "wrong-signal-path",
			signal: &dbus.Signal{
				Path: "/wrong/path",
				Name: dbusInterface + "." + dbusOwnerSignal,
				Body: []any{dbusResolvedObject, "previous owner", "new owner"},
			},
		},
		{
			name:   "wrong-bus-name",
			signal: nameOwnerChangedSignal("org.example.service", "previous owner", "new owner"),
		},
		{
			name:   "resolved-stopped",
			signal: nameOwnerChangedSignal(dbusResolvedObject, "previous owner", ""),
		},
		{
			name:   "resolved-restarted",
			signal: nameOwnerChangedSignal(dbusResolvedObject, "previous owner", "new owner"),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.isResolvedRestartSignal(tt.signal); got != tt.want {
				t.Errorf("isResolvedRestartSignal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func nameOwnerChangedSignal(body ...any) *dbus.Signal {
	return &dbus.Signal{
		Path: dbusPath,
		Name: dbusInterface + "." + dbusOwnerSignal,
		Body: body,
	}
}
