// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceclientprefs

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/serviceclientprefs/serviceclient"
	"tailscale.com/ipn"
)

func TestServiceClientPrefsSetAndGet(t *testing.T) {
	tests := []struct {
		name     string
		requests []apitype.ServiceClientPrefRequest
		want     serviceclient.Prefs
	}{
		{
			name:     "records_a_single_launch",
			requests: []apitype.ServiceClientPrefRequest{{Key: "ssh:22", Client: "terminal", Username: "rollie"}},
			want:     serviceclient.Prefs{"ssh:22": {Client: "terminal", Username: "rollie"}},
		},
		{
			name: "partial_update_preserves_existing_fields",
			requests: []apitype.ServiceClientPrefRequest{
				{Key: "ssh:22", Client: "terminal", Username: "rollie"},
				{Key: "ssh:22", Client: "iterm2"},
			},
			want: serviceclient.Prefs{"ssh:22": {Client: "iterm2", Username: "rollie"}},
		},
		{
			name: "independent_services_kept_separate",
			requests: []apitype.ServiceClientPrefRequest{
				{Key: "ssh:22", Client: "terminal"},
				{Key: "db:5432", Client: "psql", DatabaseName: "prod"},
			},
			want: serviceclient.Prefs{
				"ssh:22":  {Client: "terminal"},
				"db:5432": {Client: "psql", DatabaseName: "prod"},
			},
		},
	}

	ignoreLastUsed := cmpopts.IgnoreFields(serviceclient.Pref{}, "LastUsed")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestExtension(t, "pid")
			for _, req := range tt.requests {
				if _, err := e.setServiceClientPref(req); err != nil {
					t.Fatal(err)
				}
			}
			got, err := e.serviceClientPrefs()
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

func TestServiceClientPrefsEmptyKeyRejected(t *testing.T) {
	e := newTestExtension(t, "pid")
	_, err := e.setServiceClientPref(apitype.ServiceClientPrefRequest{Client: "terminal"})
	if !errors.Is(err, errInvalidServiceClientPref) {
		t.Errorf("want errInvalidServiceClientPref for empty key, got %v", err)
	}
}

func TestServiceClientPrefsNoCurrentProfileReturnsEmpty(t *testing.T) {
	e := newTestExtension(t, "") // no current profile
	got, err := e.serviceClientPrefs()
	if err != nil {
		t.Fatalf("want nil error for no current profile, got %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("want empty non-nil map, got %#v", got)
	}
}

func TestServiceClientPrefsRepopulatedOnProfileSwitch(t *testing.T) {
	e := newTestExtension(t, "pid0")

	// Save a pref for pid0.
	if _, err := e.setServiceClientPref(apitype.ServiceClientPrefRequest{Key: "ssh:22", Client: "terminal"}); err != nil {
		t.Fatal(err)
	}

	// Switch to a different profile; it must not see pid0's data.
	e.onChangeProfile((&ipn.LoginProfile{ID: "pid1"}).View(), ipn.PrefsView{}, false)
	if got, _ := e.serviceClientPrefs(); len(got) != 0 {
		t.Fatalf("pid1 unexpectedly saw pid0's prefs: %v", got)
	}

	// Switch back to pid0; its saved pref should be read back from disk into the cache.
	e.onChangeProfile((&ipn.LoginProfile{ID: "pid0"}).View(), ipn.PrefsView{}, false)
	got, err := e.serviceClientPrefs()
	if err != nil {
		t.Fatal(err)
	}
	if got["ssh:22"].Client != "terminal" {
		t.Errorf("after switching back, got %v, want Client=terminal", got["ssh:22"])
	}
}
