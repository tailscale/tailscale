// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestReconcileBlueprintPrefs_PresenceIsOnAbsenceIsOff verifies that
// the blueprint reconcile loop drives the bound node's prefs to a
// projection of BlueprintConfig.Prefs:
//
//   - presence in cfg.Prefs => Prefs.<field> = true
//   - absence in cfg.Prefs (but the pref IS in the supported set) =>
//     Prefs.<field> = false, regardless of prior value
//
// The "absence equals OFF" rule is what makes the blueprint the
// source of truth: if a blueprint omits pref:accept-dns, the bound
// node must NOT accept DNS even if its previous local config had
// CorpDNS=true.
//
// The v2 allowlist is three client-side prefs: accept-dns,
// accept-routes, ssh. pref:funnel is in the spec's compile-time
// allowlist but has no client-side ipn.Prefs bool to project onto, so
// it is treated as an unknown pref for projection purposes.
func TestReconcileBlueprintPrefs_PresenceIsOnAbsenceIsOff(t *testing.T) {
	for _, tt := range []struct {
		name       string
		startCorp  bool
		startRoute bool
		startSSH   bool
		bpPrefs    []string

		wantCorp  bool
		wantRoute bool
		wantSSH   bool
	}{
		{
			name:     "all_supported_prefs_on",
			bpPrefs:  []string{"pref:accept-dns", "pref:accept-routes", "pref:ssh"},
			wantCorp: true, wantRoute: true, wantSSH: true,
		},
		{
			name:     "only_accept_dns",
			bpPrefs:  []string{"pref:accept-dns"},
			wantCorp: true,
		},
		{
			name:      "silence_forces_off_overrides_prior_local",
			startCorp: true, startRoute: true, startSSH: true,
			bpPrefs: nil, // blueprint omits all prefs
			// all want* default to false: silence equals OFF.
		},
		{
			name:      "partial_silence_only_listed_prefs_on",
			startCorp: true, startRoute: true, startSSH: true,
			bpPrefs: []string{"pref:ssh"},
			wantSSH: true,
			// CorpDNS / RouteAll forced back to false despite prior on.
		},
		{
			name:     "unknown_pref_ignored_silently",
			bpPrefs:  []string{"pref:accept-dns", "pref:not-a-real-pref"},
			wantCorp: true,
		},
		{
			name:     "funnel_is_not_client_side_projected",
			bpPrefs:  []string{"pref:accept-dns", "pref:funnel"},
			wantCorp: true,
			// pref:funnel has no client-side ipn.Prefs bool; it
			// rides in the compile-time allowlist but is delivered
			// (if at all) via the existing nodecap path. Here we
			// just confirm the reconciler does not panic and does
			// not touch any other field.
		},
		{
			name:      "v1_legacy_prefs_no_longer_projected",
			startCorp: false,
			// Includes the v1.1-era pref:shields-up and pref:webclient
			// in the bp config to confirm we don't accidentally
			// resurrect them by re-introducing setters. Only
			// pref:accept-dns flips, and shields-up/webclient have
			// no observable client-side effect any more.
			bpPrefs:  []string{"pref:accept-dns", "pref:shields-up", "pref:webclient"},
			wantCorp: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			b.SetPrefsForTest(&ipn.Prefs{
				BlueprintID: "demo",
				CorpDNS:     tt.startCorp,
				RouteAll:    tt.startRoute,
				RunSSH:      tt.startSSH,
			})

			selfNode := (&tailcfg.Node{
				ID:          1,
				BlueprintID: "demo",
				BlueprintConfig: &tailcfg.BlueprintConfig{
					Prefs: tt.bpPrefs,
				},
			}).View()
			nm := &netmap.NetworkMap{SelfNode: selfNode}

			b.mu.Lock()
			b.reconcileBlueprintPrefsLocked(nm)
			b.mu.Unlock()

			got := b.pm.CurrentPrefs()
			if got.CorpDNS() != tt.wantCorp {
				t.Errorf("CorpDNS = %v; want %v", got.CorpDNS(), tt.wantCorp)
			}
			if got.RouteAll() != tt.wantRoute {
				t.Errorf("RouteAll = %v; want %v", got.RouteAll(), tt.wantRoute)
			}
			if got.RunSSH() != tt.wantSSH {
				t.Errorf("RunSSH = %v; want %v", got.RunSSH(), tt.wantSSH)
			}
		})
	}
}

// TestReconcileBlueprintPrefs_NoOpForUnboundNode verifies the
// reconcile loop is a no-op when the node has no blueprint binding;
// existing `tailscale up` users must be unaffected.
func TestReconcileBlueprintPrefs_NoOpForUnboundNode(t *testing.T) {
	b := newTestLocalBackend(t)
	b.SetPrefsForTest(&ipn.Prefs{
		CorpDNS:  true,
		RouteAll: true,
		RunSSH:   true,
	})

	// SelfNode with no BlueprintConfig — i.e. not blueprint-bound.
	selfNode := (&tailcfg.Node{ID: 1}).View()
	nm := &netmap.NetworkMap{SelfNode: selfNode}

	b.mu.Lock()
	b.reconcileBlueprintPrefsLocked(nm)
	b.mu.Unlock()

	got := b.pm.CurrentPrefs()
	if !got.CorpDNS() {
		t.Error("non-bound node had CorpDNS reconciled to false")
	}
	if !got.RouteAll() {
		t.Error("non-bound node had RouteAll reconciled to false")
	}
	if !got.RunSSH() {
		t.Error("non-bound node had RunSSH reconciled to false")
	}
}

// TestReconcileBlueprintPrefs_LegacyPrefsLeaveLocalFieldsAlone pins
// the spec v2 narrowing: pref:shields-up and pref:webclient were in
// the v1.1 allowlist but are no longer projected client-side, so a
// blueprint that omits them MUST NOT force the local ShieldsUp or
// RunWebClient bools to false. Conversely, listing them in the
// projection MUST NOT flip the bools to true.
//
// This distinguishes the v1 setter table (which had silence-forces-
// off semantics for those fields) from the v2 table (which doesn't
// know about them at all).
func TestReconcileBlueprintPrefs_LegacyPrefsLeaveLocalFieldsAlone(t *testing.T) {
	// Case 1: start with ShieldsUp=true and RunWebClient=true; omit
	// them from BlueprintConfig.Prefs. v1 would force both to false;
	// v2 must leave them alone.
	b := newTestLocalBackend(t)
	b.SetPrefsForTest(&ipn.Prefs{
		BlueprintID:  "demo",
		ShieldsUp:    true,
		RunWebClient: true,
	})
	selfNode := (&tailcfg.Node{
		ID:          1,
		BlueprintID: "demo",
		BlueprintConfig: &tailcfg.BlueprintConfig{
			Prefs: []string{"pref:accept-dns"},
		},
	}).View()
	b.mu.Lock()
	b.reconcileBlueprintPrefsLocked(&netmap.NetworkMap{SelfNode: selfNode})
	b.mu.Unlock()
	got := b.pm.CurrentPrefs()
	if !got.ShieldsUp() {
		t.Error("v2 reconciler forced ShieldsUp OFF; pref:shields-up is not in the v2 allowlist")
	}
	if !got.RunWebClient() {
		t.Error("v2 reconciler forced RunWebClient OFF; pref:webclient is not in the v2 allowlist")
	}

	// Case 2: start with ShieldsUp=false and RunWebClient=false;
	// include pref:shields-up and pref:webclient. v1 would force
	// both to true; v2 must leave them alone (unknown prefs).
	b2 := newTestLocalBackend(t)
	b2.SetPrefsForTest(&ipn.Prefs{BlueprintID: "demo"})
	selfNode2 := (&tailcfg.Node{
		ID:          1,
		BlueprintID: "demo",
		BlueprintConfig: &tailcfg.BlueprintConfig{
			Prefs: []string{"pref:shields-up", "pref:webclient"},
		},
	}).View()
	b2.mu.Lock()
	b2.reconcileBlueprintPrefsLocked(&netmap.NetworkMap{SelfNode: selfNode2})
	b2.mu.Unlock()
	got2 := b2.pm.CurrentPrefs()
	if got2.ShieldsUp() {
		t.Error("v2 reconciler set ShieldsUp ON for unknown pref:shields-up")
	}
	if got2.RunWebClient() {
		t.Error("v2 reconciler set RunWebClient ON for unknown pref:webclient")
	}
}

// TestReconcileBlueprintPrefs_NilNetmap verifies the reconcile loop
// is safe to call with nil/empty inputs (defensive against early
// daemon boot before the first netmap arrives).
func TestReconcileBlueprintPrefs_NilNetmap(t *testing.T) {
	b := newTestLocalBackend(t)
	b.SetPrefsForTest(&ipn.Prefs{BlueprintID: "demo", CorpDNS: true})

	b.mu.Lock()
	b.reconcileBlueprintPrefsLocked(nil)
	b.mu.Unlock()
	// Should not panic; prior prefs unchanged.
	if !b.pm.CurrentPrefs().CorpDNS() {
		t.Error("nil netmap should not touch prefs")
	}
}
