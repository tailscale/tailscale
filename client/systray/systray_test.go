// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package systray

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestConnectNode(t *testing.T) {
	t.Parallel()
	const (
		statusPath = "/localapi/v0/status"
		loginPath  = "/localapi/v0/login-interactive"
		prefsPath  = "/localapi/v0/prefs"
	)
	tests := []struct {
		name     string
		state    ipn.State
		failPath string
		attempts int
		want     []string
		wantErr  bool
	}{
		{
			name: "needs_login_repeated_clicks", state: ipn.NeedsLogin, attempts: 2,
			want: []string{"GET " + statusPath, "POST " + loginPath, "GET " + statusPath, "POST " + loginPath},
		},
		{
			name: "stopped", state: ipn.Stopped, attempts: 1,
			want: []string{"GET " + statusPath, "PATCH " + prefsPath},
		},
		{
			name: "status_error", state: ipn.NeedsLogin, attempts: 1, failPath: statusPath, wantErr: true,
			want: []string{"GET " + statusPath},
		},
		{
			name: "login_error", state: ipn.NeedsLogin, attempts: 1, failPath: loginPath, wantErr: true,
			want: []string{"GET " + statusPath, "POST " + loginPath},
		},
		{
			name: "prefs_error", state: ipn.Stopped, attempts: 1, failPath: prefsPath, wantErr: true,
			want: []string{"GET " + statusPath, "PATCH " + prefsPath},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requests := make(chan string, 8)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Method + " " + r.URL.Path
				if r.URL.Path == tt.failPath {
					http.Error(w, "test error", http.StatusInternalServerError)
					return
				}
				switch r.URL.Path {
				case statusPath:
					if got := r.URL.Query().Get("peers"); got != "false" {
						t.Errorf("status peers = %q, want false", got)
					}
					json.NewEncoder(w).Encode(&ipnstate.Status{BackendState: tt.state.String()})
				case loginPath:
					w.WriteHeader(http.StatusNoContent)
				case prefsPath:
					var prefs ipn.MaskedPrefs
					if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
						t.Errorf("decoding prefs: %v", err)
					} else if !prefs.WantRunningSet || !prefs.WantRunning {
						t.Errorf("connect prefs = %+v, want WantRunning=true and WantRunningSet=true", prefs)
					}
					json.NewEncoder(w).Encode(&ipn.Prefs{})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			// Simulate a menu that has not yet caught up with the daemon state.
			menu := &Menu{status: &ipnstate.Status{BackendState: ipn.Running.String()}, lc: &local.Client{
				OmitAuth: true,
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
				},
			}}
			for range tt.attempts {
				if err := menu.connectNode(t.Context()); (err != nil) != tt.wantErr {
					t.Fatalf("connectNode error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			var got []string
			for len(requests) > 0 {
				got = append(got, <-requests)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("requests = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProfileTitleMultiline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		login     string
		tailnet   string
		multiline bool
		want      string
	}{
		{"no_tailnet", "alice@example.com", "", true, "alice@example.com"},
		{"dup_exact", "example.com", "example.com", true, "example.com"},
		{"dup_casefold", "Example.com", "example.com", false, "Example.com"},
		{"distinct_multiline", "alice@example.com", "example.com", true, "alice@example.com\nexample.com"},
		{"distinct_singleline", "alice@example.com", "example.com", false, "alice@example.com (example.com)"},
		{"empty", "", "", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatProfileTitle(tt.login, tt.tailnet, tt.multiline); got != tt.want {
				t.Errorf("profileTitleMultiline; got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecommendedIsActive(t *testing.T) {
	t.Parallel()

	const (
		activeID = tailcfg.StableNodeID("active")
		suggID   = tailcfg.StableNodeID("suggestion")
	)
	usNYC := &tailcfg.Location{CountryCode: "US", City: "New York"}
	usCHI := &tailcfg.Location{CountryCode: "US", City: "Chicago"}
	seSTO := &tailcfg.Location{CountryCode: "SE", City: "Stockholm"}

	statusWith := func(activePeer *ipnstate.PeerStatus) *ipnstate.Status {
		s := &ipnstate.Status{
			ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: activeID},
		}
		if activePeer != nil {
			s.Peer = map[key.NodePublic]*ipnstate.PeerStatus{{}: activePeer}
		}
		return s
	}

	tests := []struct {
		name        string
		status      *ipnstate.Status
		suggID      tailcfg.StableNodeID
		suggCountry string
		suggCity    string
		isActive    bool
	}{
		{
			name:   "nil_status",
			status: nil,
			suggID: suggID,
		},
		{
			name:   "no_exit_node",
			status: &ipnstate.Status{},
			suggID: suggID,
		},
		{
			name:   "exit_node_id_is_zero",
			status: &ipnstate.Status{ExitNodeStatus: &ipnstate.ExitNodeStatus{}},
			suggID: suggID,
		},
		{
			name:        "exact_id_match_short-circuits",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usCHI}),
			suggID:      activeID,
			suggCountry: "US",
			suggCity:    "New York",
			isActive:    true,
		},
		{
			name:        "id_mismatch_but_same_city",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usNYC}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
			isActive:    true,
		},
		{
			name:        "different_city",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usCHI}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:        "different_country",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID, Location: seSTO}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:   "id_mismatch_suggestion_has_no_location",
			status: statusWith(&ipnstate.PeerStatus{ID: activeID, Location: usNYC}),
			suggID: suggID,
		},
		{
			name:        "id_mismatch_active_peer_has_no_location",
			status:      statusWith(&ipnstate.PeerStatus{ID: activeID}),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
		{
			name:        "active_peer_not_in_status",
			status:      statusWith(nil),
			suggID:      suggID,
			suggCountry: "US",
			suggCity:    "New York",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isExitNodeActive := recommendedIsActive(tt.status, tt.suggID, tt.suggCountry, tt.suggCity)
			if isExitNodeActive != tt.isActive {
				t.Errorf("recommendedIsActive; got %v, want %v", isExitNodeActive, tt.isActive)
			}
		})
	}
}
