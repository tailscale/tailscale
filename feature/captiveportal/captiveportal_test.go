// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captiveportal

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tsd"
	"tailscale.com/util/eventbus/eventbustest"
)

var (
	testConnWarnable1 = health.Register(&health.Warnable{
		Code:                "test-captiveportal-conn-1",
		Title:               "Test connectivity 1",
		Severity:            health.SeverityMedium,
		Text:                health.StaticMessage("test connectivity warning 1"),
		ImpactsConnectivity: true,
	})
	testConnWarnable2 = health.Register(&health.Warnable{
		Code:                "test-captiveportal-conn-2",
		Title:               "Test connectivity 2",
		Severity:            health.SeverityMedium,
		Text:                health.StaticMessage("test connectivity warning 2"),
		ImpactsConnectivity: true,
	})
	testNonConnWarnable = health.Register(&health.Warnable{
		Code:                "test-captiveportal-non-conn",
		Title:               "Test non-connectivity",
		Severity:            health.SeverityLow,
		Text:                health.StaticMessage("test non-connectivity warning"),
		ImpactsConnectivity: false,
	})
)

type testSafeBackend struct {
	ipnext.SafeBackend
	sys *tsd.System
}

func (b *testSafeBackend) Sys() *tsd.System { return b.sys }

type testProfileServices struct {
	ipnext.ProfileServices
	prefs ipn.PrefsView
}

func (p *testProfileServices) CurrentPrefs() ipn.PrefsView { return p.prefs }

type testHost struct {
	ipnext.Host
	hooks ipnext.Hooks
	prefs ipn.PrefsView
}

func (h *testHost) Hooks() *ipnext.Hooks             { return &h.hooks }
func (h *testHost) Profiles() ipnext.ProfileServices { return &testProfileServices{prefs: h.prefs} }

func newTestExtension(t *testing.T) (*Extension, *health.Tracker, func() int) {
	t.Helper()
	bus := eventbustest.NewBus(t)
	sys := tsd.NewSystemWithBus(bus)
	sys.ControlKnobs().DisableCaptivePortalDetection.Store(true)

	var (
		mu       sync.Mutex
		triggers int
	)
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "triggering captive portal detection") {
			mu.Lock()
			triggers++
			mu.Unlock()
		}
	}
	triggerCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return triggers
	}

	ext, err := newExtension(logf, &testSafeBackend{sys: sys})
	if err != nil {
		t.Fatalf("newExtension: %v", err)
	}
	e := ext.(*Extension)
	if err := e.Init(&testHost{prefs: (&ipn.Prefs{WantRunning: true}).View()}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { e.Shutdown() })

	e.onBackendStateChange(ipn.Running)
	return e, sys.HealthTracker.Get(), triggerCount
}

func TestOnHealthChangeDeduplicatesTrigger(t *testing.T) {
	if !buildfeatures.HasHealth {
		t.Skip("health feature omitted")
	}

	synctest.Test(t, func(t *testing.T) {
		_, ht, triggerCount := newTestExtension(t)

		ht.SetUnhealthy(testConnWarnable1, nil)
		synctest.Wait()
		if got := triggerCount(); got != 1 {
			t.Fatalf("trigger count after initial connectivity warning = %d, want 1", got)
		}

		// Subsequent health updates while connectivity remains impacted should
		// not keep logging or re-triggering captive portal detection.
		ht.SetUnhealthy(testNonConnWarnable, nil)
		synctest.Wait()
		ht.SetUnhealthy(testConnWarnable2, nil)
		synctest.Wait()
		ht.SetHealthy(testConnWarnable2)
		synctest.Wait()
		ht.SetHealthy(testNonConnWarnable)
		synctest.Wait()
		ht.SetUnhealthy(captivePortalWarnable, nil)
		synctest.Wait()

		if got := triggerCount(); got != 1 {
			t.Fatalf("trigger count after additional health updates = %d, want 1", got)
		}

		// Clearing all connectivity-impacting warnings clears the captive
		// portal warning and re-arms detection for a future outage.
		ht.SetHealthy(testConnWarnable1)
		synctest.Wait()
		if ht.IsUnhealthy(captivePortalWarnable) {
			t.Fatal("captivePortalWarnable remained unhealthy after connectivity recovered")
		}

		ht.SetUnhealthy(testConnWarnable1, nil)
		synctest.Wait()
		if got := triggerCount(); got != 2 {
			t.Fatalf("trigger count after second connectivity warning = %d, want 2", got)
		}
	})
}

func TestOnHealthChangeClearsLateCaptivePortalWarnable(t *testing.T) {
	if !buildfeatures.HasHealth {
		t.Skip("health feature omitted")
	}

	synctest.Test(t, func(t *testing.T) {
		_, ht, triggerCount := newTestExtension(t)

		ht.SetUnhealthy(testConnWarnable1, nil)
		synctest.Wait()
		ht.SetHealthy(testConnWarnable1)
		synctest.Wait()

		// Simulate a late captive portal result arriving after connectivity
		// already recovered.
		ht.SetUnhealthy(captivePortalWarnable, nil)
		synctest.Wait()

		if ht.IsUnhealthy(captivePortalWarnable) {
			t.Fatal("captivePortalWarnable remained unhealthy when no other connectivity warnings are active")
		}
		if got := triggerCount(); got != 1 {
			t.Fatalf("trigger count = %d, want 1", got)
		}
	})
}
