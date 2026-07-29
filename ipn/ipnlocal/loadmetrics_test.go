// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"runtime"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/opt"
)

func TestCheckCollectLoadMetrics(t *testing.T) {
	tests := []struct {
		name    string
		prefs   *ipn.Prefs
		wantErr string // substring; "" means the prefs must be accepted
	}{
		{
			name:  "unset is always fine",
			prefs: &ipn.Prefs{},
		},
		{
			name:  "explicitly disabled is always fine",
			prefs: &ipn.Prefs{CollectLoadMetrics: opt.NewBool(false)},
		},
		{
			name: "disabled on an App Connector is fine",
			prefs: &ipn.Prefs{
				CollectLoadMetrics: opt.NewBool(false),
				AppConnector:       ipn.AppConnectorPrefs{Advertise: true},
			},
		},
		{
			name: "enabled on an App Connector is rejected",
			prefs: &ipn.Prefs{
				CollectLoadMetrics: opt.NewBool(true),
				AppConnector:       ipn.AppConnectorPrefs{Advertise: true},
			},
			wantErr: "not supported on App Connectors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCollectLoadMetrics(tt.prefs)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkCollectLoadMetrics() = %v; want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkCollectLoadMetrics() = nil; want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("checkCollectLoadMetrics() = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestCheckCollectLoadMetricsPlatform covers the platform gate: the counting
// hook is only wired up on Linux, so accepting the pref elsewhere would leave
// it silently inert.
func TestCheckCollectLoadMetricsPlatform(t *testing.T) {
	p := &ipn.Prefs{CollectLoadMetrics: opt.NewBool(true)}
	err := checkCollectLoadMetrics(p)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("checkCollectLoadMetrics() on linux = %v; want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("checkCollectLoadMetrics() on %s = nil; want an error", runtime.GOOS)
	}
	if !strings.Contains(err.Error(), "Linux") {
		t.Errorf("checkCollectLoadMetrics() on %s = %v; want the error to mention Linux", runtime.GOOS, err)
	}
}

// TestCheckPrefsRejectsLoadMetricsOnAppConnector verifies the check is actually
// reached through checkPrefsLocked, which is the shared gate for tailscale set,
// tailscale up, and config-file loads.
func TestCheckPrefsRejectsLoadMetricsOnAppConnector(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("pref is Linux-only; running on %s", runtime.GOOS)
	}
	b := newTestLocalBackend(t)

	p := &ipn.Prefs{
		ControlURL:         ipn.DefaultControlURL,
		CollectLoadMetrics: opt.NewBool(true),
		AppConnector:       ipn.AppConnectorPrefs{Advertise: true},
	}
	err := b.CheckPrefs(p)
	if err == nil {
		t.Fatal("CheckPrefs accepted load metrics on an App Connector; want an error")
	}
	if !strings.Contains(err.Error(), "not supported on App Connectors") {
		t.Errorf("CheckPrefs error = %v; want it to mention App Connectors", err)
	}
}
