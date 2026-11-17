// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logid"
	"tailscale.com/util/httpm"
	"tailscale.com/util/set"
	"tailscale.com/wgengine"
)

func newC2NUsernameBackend(t *testing.T) *ipnlocal.LocalBackend {
	t.Helper()
	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystem()
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(eng)
	sys.Set(new(mem.Store))
	b, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Shutdown)
	return b
}

func c2nSSHUsernamesResponse(t *testing.T, b *ipnlocal.LocalBackend, method, body string) tailcfg.C2NSSHUsernamesResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/ssh/usernames", strings.NewReader(body))
	handleC2NSSHUsernames(b, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var res tailcfg.C2NSSHUsernamesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return res
}

func TestHandleC2NSSHUsernamesExclude(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("local username hook is not used on darwin")
	}
	b := newC2NUsernameBackend(t)
	prefs := ipn.NewPrefs()
	prefs.RunSSH = true
	b.ForTest().SetPrefs(prefs)
	if !b.ShouldRunSSH() {
		t.Skip("SSH disabled by environment")
	}

	tstest.Replace(t, &hookLocalUsernames, func() ([]string, error) {
		return []string{"alice", "bob"}, nil
	})
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"true-not-yet-in-results", `{"Exclude":{"alice":true}}`, []string{"bob"}},
		{"false", `{"Exclude":{"alice":false}}`, []string{"alice", "bob"}},
		{"empty", `{"Exclude":{}}`, []string{"alice", "bob"}},
		{"absent", `{}`, []string{"alice", "bob"}},
		{"missing-username", `{"Exclude":{"not-a-user":true}}`, []string{"alice", "bob"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := c2nSSHUsernamesResponse(t, b, httpm.POST, tt.body)
			if !slices.Equal(got.Usernames, tt.want) {
				t.Errorf("Usernames = %q; want %q", got.Usernames, tt.want)
			}
		})
	}
}

func TestHandleC2NSSHUsernamesMax(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("local username hook is not used on darwin")
	}
	b := newC2NUsernameBackend(t)
	prefs := ipn.NewPrefs()
	prefs.RunSSH = true
	b.ForTest().SetPrefs(prefs)
	if !b.ShouldRunSSH() {
		t.Skip("SSH disabled by environment")
	}

	names := make([]string, 120)
	for i := range names {
		names[i] = fmt.Sprintf("user%03d", i)
	}
	tstest.Replace(t, &hookLocalUsernames, func() ([]string, error) {
		return names, nil
	})
	for _, tt := range []struct {
		name, method, body string
		want               int
	}{
		{"GET-default", httpm.GET, "", 10},
		{"zero-default", httpm.POST, `{"Max":0}`, 10},
		{"one", httpm.POST, `{"Max":1}`, 1},
		{"100", httpm.POST, `{"Max":100}`, 100},
		{"above-100-clamped", httpm.POST, `{"Max":101}`, 100},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := c2nSSHUsernamesResponse(t, b, tt.method, tt.body)
			if !slices.Equal(got.Usernames, names[:tt.want]) {
				t.Errorf("Usernames = %q; want first %d generated usernames", got.Usernames, tt.want)
			}
		})
	}
}

func TestHandleC2NSSHUsernamesDisabled(t *testing.T) {
	b := newC2NUsernameBackend(t)
	if b.ShouldRunSSH() {
		t.Fatal("new backend unexpectedly has SSH enabled")
	}
	tstest.Replace(t, &hookLocalUsernames, func() ([]string, error) {
		t.Fatal("looked up usernames with SSH disabled")
		return nil, nil
	})
	res := c2nSSHUsernamesResponse(t, b, httpm.POST, `{"Exclude":{"alice":true}}`)
	if res.Usernames != nil {
		t.Errorf("Usernames = %q; want nil for disabled SSH", res.Usernames)
	}
}

func TestAppendSSHUsernameHint(t *testing.T) {
	tests := []struct {
		name    string
		names   []string
		u       string
		exclude set.Set[string]
		max     int
		want    []string
	}{
		{
			name: "append",
			u:    "alice",
			max:  10,
			want: []string{"alice"},
		},
		{
			name:  "dedupe",
			names: []string{"alice"},
			u:     "alice",
			max:   10,
			want:  []string{"alice"},
		},
		{
			name:    "excluded",
			names:   []string{"alice"},
			u:       "alice",
			exclude: set.SetOf([]string{"alice"}),
			max:     10,
			want:    []string{"alice"},
		},
		{
			name: "service-account-skipped",
			u:    "daemon",
			max:  10,
			want: nil,
		},
		{
			name:  "capped-exactly-at-max",
			names: []string{"alice", "bob", "carol"},
			u:     "dave",
			max:   3,
			want:  []string{"alice", "bob", "carol"},
		},
		{
			name:  "room-for-one-more",
			names: []string{"alice", "bob"},
			u:     "carol",
			max:   3,
			want:  []string{"alice", "bob", "carol"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendSSHUsernameHint(tt.names, tt.u, tt.exclude, tt.max)
			if len(got) != len(tt.want) {
				t.Fatalf("appendSSHUsernameHint(%q) = %q; want %q", tt.u, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("appendSSHUsernameHint(%q) = %q; want %q", tt.u, got, tt.want)
				}
			}
		})
	}
}
