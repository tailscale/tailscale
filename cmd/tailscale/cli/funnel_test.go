// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"reflect"
	"testing"
	"time"
)

func TestFunnelAuthFromFlags(t *testing.T) {
	tests := []struct {
		name    string
		auth    bool
		allow   string
		ttl     time.Duration
		wantNil bool
		wantAll []string
		wantTTL time.Duration
		wantErr bool
	}{
		{name: "no auth is nil (unchanged behavior)", auth: false, wantNil: true},
		{name: "no auth ignores stray allow", auth: false, allow: "x@y.com", wantNil: true},
		{name: "auth any user", auth: true, wantAll: nil},
		{name: "auth exact email", auth: true, allow: "alice@example.com", wantAll: []string{"alice@example.com"}},
		{name: "auth domain + tailnet + exact", auth: true, allow: "*@example.com, bob@x.com ,tailnet:example.ts.net",
			wantAll: []string{"*@example.com", "bob@x.com", "tailnet:example.ts.net"}},
		{name: "auth with ttl", auth: true, ttl: 2 * time.Hour, wantTTL: 2 * time.Hour},
		{name: "invalid: bare word", auth: true, allow: "notanemail", wantErr: true},
		{name: "invalid: domain without dot", auth: true, allow: "*@localhost", wantErr: true},
		{name: "invalid: empty tailnet", auth: true, allow: "tailnet:", wantErr: true},
		{name: "invalid: negative ttl", auth: true, ttl: -time.Second, wantErr: true},
		{name: "invalid: double at", auth: true, allow: "a@@b.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := funnelAuthFromFlags(tt.auth, tt.allow, tt.ttl)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil FunnelAuth, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil FunnelAuth")
			}
			if got.Provider != "tailscale" {
				t.Errorf("Provider = %q; want tailscale", got.Provider)
			}
			if !reflect.DeepEqual(got.Allow, tt.wantAll) {
				t.Errorf("Allow = %v; want %v", got.Allow, tt.wantAll)
			}
			if got.SessionTTL != tt.wantTTL {
				t.Errorf("SessionTTL = %v; want %v", got.SessionTTL, tt.wantTTL)
			}
		})
	}
}

func TestFunnelAuthPostureLine(t *testing.T) {
	got, err := funnelAuthFromFlags(true, "*@example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if line := funnelAuthPostureLine(got); line == "" || line == funnelAuthPostureLine(nil) {
		t.Errorf("authenticated posture line unexpectedly empty or same as public: %q", line)
	}
	if line := funnelAuthPostureLine(nil); line == "" {
		t.Error("public posture line should be non-empty")
	}
}
