// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
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

// TestConfigFileRejectsLoadMetricsOnAppConnector checks the config-file paths.
// checkPrefsLocked is the shared gate for tailscale set and tailscale up, but
// initPrefsFromConfig and setConfigLocked both went straight from
// conf.Parsed.ToPrefs to SetPrefs/setPrefsLocked, so the check never ran and a
// config file could turn on load metrics on an App Connector.
func TestConfigFileRejectsLoadMetricsOnAppConnector(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("pref is Linux-only; running on %s", runtime.GOOS)
	}
	conf := &conffile.Config{
		Path: "/dev/null",
		Parsed: ipn.ConfigVAlpha{
			Version:            "alpha0",
			CollectLoadMetrics: "true",
			AppConnector:       &ipn.AppConnectorPrefs{Advertise: true},
		},
	}
	sys := tsd.NewSystem()
	sys.Set(new(mem.Store))
	eng, err := wgengine.NewFakeUserspaceEngine(logger.Discard, sys.Set,
		sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	if _, ok := sys.Engine.GetOK(); !ok {
		sys.Set(eng)
	}
	if _, ok := sys.Dialer.GetOK(); !ok {
		sys.Set(tsdial.NewDialer(netmon.NewStatic()))
	}
	sys.InitialConfig = conf

	// An invalid config file must fail startup, the same way a config with
	// unmasked AdvertiseRoutes already does, rather than silently starting with
	// 4 series per DNS-discovered /32.
	b, err := NewLocalBackend(logger.Discard, logid.PublicID{}, sys, 0)
	if err == nil {
		t.Cleanup(b.Shutdown)
		if got := b.Prefs().CollectLoadMetrics(); got.EqualBool(true) {
			t.Errorf("CollectLoadMetrics = %v after a config file that also advertises an "+
				"App Connector; want it rejected or cleared", got)
		}
		return
	}
	if !strings.Contains(err.Error(), "not supported on App Connectors") {
		t.Errorf("NewLocalBackend error = %v; want it to mention App Connectors", err)
	}
}

// TestReloadConfigRejectsLoadMetricsOnAppConnector is the runtime counterpart:
// ReloadConfig -> setConfigLocked.
func TestReloadConfigRejectsLoadMetricsOnAppConnector(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("pref is Linux-only; running on %s", runtime.GOOS)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tailscale.conf")

	initial := ipn.ConfigVAlpha{Version: "alpha0", Hostname: ptrTo("h1")}
	writeConf(t, path, initial)
	sys := tsd.NewSystem()
	sys.InitialConfig = &conffile.Config{Path: path, Parsed: initial}
	b := newTestLocalBackendWithSys(t, sys)

	// Now turn on the disallowed combination and reload.
	writeConf(t, path, ipn.ConfigVAlpha{
		Version:            "alpha0",
		Hostname:           ptrTo("h1"),
		CollectLoadMetrics: "true",
		AppConnector:       &ipn.AppConnectorPrefs{Advertise: true},
	})
	if _, err := b.ReloadConfig(); err == nil {
		if got := b.Prefs().CollectLoadMetrics(); got.EqualBool(true) {
			t.Errorf("ReloadConfig accepted load metrics on an App Connector and left "+
				"CollectLoadMetrics = %v", got)
		}
	}
}

// TestPersistedBadLoadMetricsPrefsSelfHeal covers the secondary wedge:
// checkCollectLoadMetrics is a whole-prefs invariant, so once prefs hold the
// disallowed combination every later EditPrefs fails, even unrelated ones like
// setting a hostname. Loading such prefs must clear the pref instead, following
// the AutoUpdate.Apply precedent in loadSavedPrefs.
func TestPersistedBadLoadMetricsPrefsSelfHeal(t *testing.T) {
	store := new(mem.Store)
	pm, err := newProfileManagerWithGOOS(store, logger.Discard,
		health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}

	// Persist the disallowed combination, as an older client or a config file
	// written before the check existed could have.
	p := pm.CurrentPrefs().AsStruct()
	p.ControlURL = ipn.DefaultControlURL
	p.Persist = &persist.Persist{NodeID: "node-1", UserProfile: tailcfg.UserProfile{
		ID: 1, LoginName: "user@example.com",
	}}
	p.CollectLoadMetrics = opt.NewBool(true)
	p.AppConnector = ipn.AppConnectorPrefs{Advertise: true}
	if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatalf("SetPrefs: %v", err)
	}
	if !pm.CurrentPrefs().CollectLoadMetrics().EqualBool(true) {
		t.Fatal("SetPrefs did not persist CollectLoadMetrics")
	}

	// Reloading must self-heal rather than leave prefs unable to be edited.
	pm2, err := newProfileManagerWithGOOS(store, logger.Discard,
		health.NewTracker(eventbustest.NewBus(t)), "linux")
	if err != nil {
		t.Fatal(err)
	}
	got := pm2.CurrentPrefs()
	if got.CollectLoadMetrics().EqualBool(true) {
		t.Error("the disallowed CollectLoadMetrics+AppConnector combination survived a " +
			"reload; every later EditPrefs would fail")
	}
	if !got.AppConnector().Advertise {
		t.Error("AppConnector.Advertise was cleared; the load metrics pref is the one to drop")
	}
	// And the healed prefs pass the gate, so EditPrefs is not wedged.
	if err := checkCollectLoadMetrics(got.AsStruct()); err != nil {
		t.Errorf("healed prefs still fail the check: %v", err)
	}
}

func writeConf(t *testing.T, path string, c ipn.ConfigVAlpha) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
}

func ptrTo[T any](v T) *T { return &v }
