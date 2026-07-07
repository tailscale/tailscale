// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
)

func TestServicePrefsSetAndGet(t *testing.T) {
	tests := []struct {
		name     string
		requests []apitype.ServicePrefRequest
		want     ipn.ServicePrefs
	}{
		{
			name:     "records_a_single_launch",
			requests: []apitype.ServicePrefRequest{{Key: "ssh:22", Client: "terminal", Username: "rollie"}},
			want:     ipn.ServicePrefs{"ssh:22": {Client: "terminal", Username: "rollie"}},
		},
		{
			name: "partial_update_preserves_existing_fields",
			requests: []apitype.ServicePrefRequest{
				{Key: "ssh:22", Client: "terminal", Username: "rollie"},
				{Key: "ssh:22", Client: "iterm2"},
			},
			want: ipn.ServicePrefs{"ssh:22": {Client: "iterm2", Username: "rollie"}},
		},
		{
			name: "independent_services_kept_separate",
			requests: []apitype.ServicePrefRequest{
				{Key: "ssh:22", Client: "terminal"},
				{Key: "db:5432", Client: "psql", DatabaseName: "prod"},
			},
			want: ipn.ServicePrefs{
				"ssh:22":  {Client: "terminal"},
				"db:5432": {Client: "psql", DatabaseName: "prod"},
			},
		},
	}

	ignoreLastUsed := cmpopts.IgnoreFields(ipn.ServicePref{}, "LastUsed")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			backend := newTestBackend(t)

			for _, req := range tt.requests {
				if _, err := backend.SetServicePref(ctx, req); err != nil {
					t.Fatal(err)
				}
			}

			got, err := backend.ServicePrefs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got, ignoreLastUsed, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
			for key := range tt.want {
				if got[key].LastUsed.IsZero() {
					t.Errorf("%s: LastUsed was not stamped", key)
				}
			}
		})
	}
}

func TestServicePrefsDeletedForProfile(t *testing.T) {
	ctx := t.Context()
	backend := newTestBackend(t)
	pid := backend.CurrentProfile().ID()

	if _, err := backend.SetServicePref(ctx, apitype.ServicePrefRequest{Key: "ssh:22", Client: "terminal"}); err != nil {
		t.Fatal(err)
	}
	if got, err := backend.ServicePrefs(ctx); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 {
		t.Fatalf("setup: want 1 pref, got %v", got)
	}

	backend.deleteServicePrefsForProfile(backend.getServicePrefsStore(), pid)

	got, err := backend.ServicePrefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("prefs not deleted for profile %q: %v", pid, got)
	}
}
