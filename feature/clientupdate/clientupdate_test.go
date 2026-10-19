// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package clientupdate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/httpm"
)

// fakeBackend is a minimal [ipnext.SafeBackend] for tests. Only Clock is
// used by the tests below; Sys and TailscaleVarRoot are never called.
type fakeBackend struct {
	clock tstime.Clock
}

func (f *fakeBackend) Sys() *tsd.System         { return nil }
func (f *fakeBackend) Clock() tstime.Clock      { return f.clock }
func (f *fakeBackend) TailscaleVarRoot() string { return "" }

func newTestExtension(clock *tstest.Clock) *extension {
	return &extension{
		logf: logger.Discard,
		sb:   &fakeBackend{clock: clock},
	}
}

// TestServeUpdateInstallRequiresWrite verifies that the update/install
// localapi handler denies requests from clients without write permission,
// i.e. non-root, non-operator local users.
func TestServeUpdateInstallRequiresWrite(t *testing.T) {
	h := &localapi.Handler{PermitWrite: false}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(httpm.POST, "/localapi/v0/update/install", nil)
	serveUpdateInstall(h, rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func peerStatus(active bool) *ipnstate.PeerStatus {
	return &ipnstate.PeerStatus{Active: active}
}

func TestAllPeersIdle(t *testing.T) {
	tests := []struct {
		name string
		st   *ipnstate.Status
		want bool
	}{
		{"no_peers", &ipnstate.Status{}, true},
		{
			"all_inactive",
			&ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				key.NewNode().Public(): peerStatus(false),
				key.NewNode().Public(): peerStatus(false),
			}},
			true,
		},
		{
			"one_active",
			&ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				key.NewNode().Public(): peerStatus(false),
				key.NewNode().Public(): peerStatus(true),
			}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allPeersIdle(tt.st); got != tt.want {
				t.Errorf("allPeersIdle() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecideAutoUpdateApply covers the deferral/force-through state machine
// in isolation, without needing a real hourly ticker or a fake wgengine.
func TestDecideAutoUpdateApply(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := tstest.NewClock(tstest.ClockOpts{Start: start})
	e := newTestExtension(clock)

	setForceAfter := func(d time.Duration) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.prefs = (&ipn.Prefs{
			AutoUpdate: ipn.AutoUpdatePrefs{
				Apply:      opt.NewBool(true),
				ForceAfter: d,
			},
		}).View()
	}

	t.Run("idle_always_applies_and_clears_deferral", func(t *testing.T) {
		setForceAfter(0)
		apply, deferredSince := e.decideAutoUpdateApply(true, time.Time{})
		if !apply {
			t.Error("apply = false, want true when idle")
		}
		if !deferredSince.IsZero() {
			t.Errorf("deferredSince = %v, want zero", deferredSince)
		}
	})

	t.Run("not_idle_forceAfter_zero_never_applies", func(t *testing.T) {
		setForceAfter(0)
		var deferredSince time.Time
		for i := 0; i < 5; i++ {
			clock.Advance(24 * time.Hour)
			var apply bool
			apply, deferredSince = e.decideAutoUpdateApply(false, deferredSince)
			if apply {
				t.Fatalf("iteration %d: apply = true, want false (forceAfter disabled)", i)
			}
		}
		if !deferredSince.IsZero() {
			t.Errorf("deferredSince = %v, want zero (unused when forceAfter is 0)", deferredSince)
		}
	})

	t.Run("not_idle_forceAfter_set_starts_deferral_then_forces", func(t *testing.T) {
		const forceAfter = 48 * time.Hour
		setForceAfter(forceAfter)

		// First non-idle tick: starts the deferral clock, doesn't apply yet.
		apply, deferredSince := e.decideAutoUpdateApply(false, time.Time{})
		if apply {
			t.Fatal("apply = true on first non-idle tick, want false")
		}
		if deferredSince.IsZero() {
			t.Fatal("deferredSince is zero after first non-idle tick, want non-zero")
		}
		firstDeferredSince := deferredSince

		// Still within forceAfter: keep deferring.
		clock.Advance(forceAfter - time.Minute)
		apply, deferredSince = e.decideAutoUpdateApply(false, deferredSince)
		if apply {
			t.Fatal("apply = true before forceAfter elapsed, want false")
		}
		if !deferredSince.Equal(firstDeferredSince) {
			t.Errorf("deferredSince changed to %v while still deferring, want unchanged %v", deferredSince, firstDeferredSince)
		}

		// Past forceAfter: forces the update through and clears the deferral.
		clock.Advance(2 * time.Minute)
		apply, deferredSince = e.decideAutoUpdateApply(false, deferredSince)
		if !apply {
			t.Fatal("apply = false after forceAfter elapsed, want true")
		}
		if !deferredSince.IsZero() {
			t.Errorf("deferredSince = %v after forcing, want zero", deferredSince)
		}
	})

	t.Run("disabling_forceAfter_drops_deferral_so_reenabling_starts_fresh", func(t *testing.T) {
		const forceAfter = 48 * time.Hour
		setForceAfter(forceAfter)

		_, deferredSince := e.decideAutoUpdateApply(false, time.Time{})
		if deferredSince.IsZero() {
			t.Fatal("deferredSince is zero after non-idle tick, want non-zero")
		}

		setForceAfter(0)
		clock.Advance(time.Hour)
		apply, deferredSince := e.decideAutoUpdateApply(false, deferredSince)
		if apply {
			t.Fatal("apply = true with forceAfter disabled, want false")
		}
		if !deferredSince.IsZero() {
			t.Fatalf("deferredSince = %v after disabling forceAfter, want zero", deferredSince)
		}

		// Well past the original deferral start: re-enabling must not force
		// immediately based on the stale timestamp.
		clock.Advance(7 * 24 * time.Hour)
		setForceAfter(forceAfter)
		apply, deferredSince = e.decideAutoUpdateApply(false, deferredSince)
		if apply {
			t.Fatal("apply = true right after re-enabling forceAfter, want false (fresh countdown)")
		}
		if !deferredSince.Equal(clock.Now()) {
			t.Errorf("deferredSince = %v, want %v (fresh countdown from now)", deferredSince, clock.Now())
		}
	})

	t.Run("idle_tick_in_the_middle_of_a_deferral_clears_it", func(t *testing.T) {
		const forceAfter = 48 * time.Hour
		setForceAfter(forceAfter)

		_, deferredSince := e.decideAutoUpdateApply(false, time.Time{})
		if deferredSince.IsZero() {
			t.Fatal("deferredSince is zero after non-idle tick, want non-zero")
		}
		clock.Advance(time.Hour)
		apply, deferredSince := e.decideAutoUpdateApply(true, deferredSince)
		if !apply {
			t.Error("apply = false on idle tick, want true")
		}
		if !deferredSince.IsZero() {
			t.Errorf("deferredSince = %v after an idle tick, want zero", deferredSince)
		}
	})
}

// TestUpdateAutoUpdateLocked verifies that the periodic checker is started
// and stopped in response to the AutoUpdate.Apply pref, independent of
// connection state (the bug this logic replaced: the old implementation
// also required the node to be disconnected).
func TestUpdateAutoUpdateLocked(t *testing.T) {
	restore := feature.HookCanAutoUpdate.SetForTest(func() bool { return true })
	defer restore()

	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	e := newTestExtension(clock)
	t.Cleanup(e.stopAutoUpdate)

	applyOnPrefs := (&ipn.Prefs{
		AutoUpdate: ipn.AutoUpdatePrefs{Apply: opt.NewBool(true)},
	}).View()
	applyOffPrefs := (&ipn.Prefs{
		AutoUpdate: ipn.AutoUpdatePrefs{Apply: opt.NewBool(false)},
	}).View()

	e.mu.Lock()
	e.prefs = applyOnPrefs
	e.updateAutoUpdateLocked()
	running := e.autoUpdateCancel != nil
	e.mu.Unlock()
	if !running {
		t.Error("checker not started with AutoUpdate.Apply=true")
	}

	e.mu.Lock()
	e.prefs = applyOffPrefs
	e.updateAutoUpdateLocked()
	running = e.autoUpdateCancel != nil
	e.mu.Unlock()
	if running {
		t.Error("checker still running after AutoUpdate.Apply=false")
	}

	// Re-enable and verify it starts again; this also exercises the cleanup
	// path at the end of the test (via t.Cleanup(e.stopAutoUpdate)).
	e.mu.Lock()
	e.prefs = applyOnPrefs
	e.updateAutoUpdateLocked()
	running = e.autoUpdateCancel != nil
	e.mu.Unlock()
	if !running {
		t.Error("checker not restarted after re-enabling AutoUpdate.Apply")
	}
}
