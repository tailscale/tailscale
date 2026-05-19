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
func TestReconcileBlueprintPrefs_PresenceIsOnAbsenceIsOff(t *testing.T) {
	for _, tt := range []struct {
		name           string
		startCorp      bool
		startRoute     bool
		startSSH       bool
		startShields   bool
		startWebClient bool
		bpPrefs        []string

		wantCorp      bool
		wantRoute     bool
		wantSSH       bool
		wantShields   bool
		wantWebClient bool
	}{
		{
			name:     "all_supported_prefs_on",
			bpPrefs:  []string{"pref:accept-dns", "pref:accept-routes", "pref:ssh", "pref:shields-up", "pref:webclient"},
			wantCorp: true, wantRoute: true, wantSSH: true, wantShields: true, wantWebClient: true,
		},
		{
			name:     "only_accept_dns",
			bpPrefs:  []string{"pref:accept-dns"},
			wantCorp: true,
		},
		{
			name:      "silence_forces_off_overrides_prior_local",
			startCorp: true, startRoute: true, startSSH: true, startShields: true, startWebClient: true,
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			b.SetPrefsForTest(&ipn.Prefs{
				BlueprintID:  "demo",
				CorpDNS:      tt.startCorp,
				RouteAll:     tt.startRoute,
				RunSSH:       tt.startSSH,
				ShieldsUp:    tt.startShields,
				RunWebClient: tt.startWebClient,
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
			if got.ShieldsUp() != tt.wantShields {
				t.Errorf("ShieldsUp = %v; want %v", got.ShieldsUp(), tt.wantShields)
			}
			if got.RunWebClient() != tt.wantWebClient {
				t.Errorf("RunWebClient = %v; want %v", got.RunWebClient(), tt.wantWebClient)
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
