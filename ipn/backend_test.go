// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"go/types"
	"maps"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"tailscale.com/health"
	"tailscale.com/types/empty"
	"tailscale.com/util/mak"
)

func TestNotifyString(t *testing.T) {
	for _, tt := range []struct {
		name     string
		value    Notify
		expected string
	}{
		{
			name:     "notify-empty",
			value:    Notify{},
			expected: "Notify{}",
		},
		{
			name:     "notify-with-login-finished",
			value:    Notify{LoginFinished: &empty.Message{}},
			expected: "Notify{LoginFinished}",
		},
		{
			name:     "notify-with-multiple-fields",
			value:    Notify{LoginFinished: &empty.Message{}, Health: &health.State{}},
			expected: "Notify{LoginFinished Health{...}}",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.value.String()
			if actual != tt.expected {
				t.Fatalf("expected=%q, actual=%q", tt.expected, actual)
			}
		})
	}
}

func TestPeerWireGuardStateJSON(t *testing.T) {
	tests := []struct {
		state PeerWireGuardState
		json  string
	}{
		{PeerWireGuardStateNone, `"none"`},
		{PeerWireGuardStateHandshake, `"handshake"`},
		{PeerWireGuardStateEstablished, `"established"`},
		{PeerWireGuardStateExpired, `"expired"`},
	}
	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			got, err := json.Marshal(tt.state)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tt.json {
				t.Errorf("Marshal(%v) = %s; want %s", tt.state, got, tt.json)
			}
			var back PeerWireGuardState
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if back != tt.state {
				t.Errorf("round-trip = %v; want %v", back, tt.state)
			}
		})
	}

	var bad PeerWireGuardState
	if err := json.Unmarshal([]byte(`"bogus"`), &bad); err == nil {
		t.Errorf("Unmarshal of bogus value did not return an error")
	}
}

func TestValidateNotifyWatchOpt(t *testing.T) {
	tests := []struct {
		name    string
		mask    NotifyWatchOpt
		wantErr bool
	}{
		{
			name: "legacy-rate-limit-only",
			mask: NotifyRateLimit,
		},
		{
			name: "peer-changes-without-rate-limit",
			mask: NotifyPeerChanges | NotifyPeerPatches | NotifyNoNetMap | NotifyInitialStatus,
		},
		{
			name: "in-process-no-disconnect",
			mask: NotifyInProcessNoDisconnect | NotifyPeerChanges,
		},
		{
			name:    "rate-limit-with-peer-changes",
			mask:    NotifyRateLimit | NotifyPeerChanges,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-peer-patches",
			mask:    NotifyRateLimit | NotifyPeerPatches,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-no-netmap",
			mask:    NotifyRateLimit | NotifyNoNetMap,
			wantErr: true,
		},
		{
			name:    "rate-limit-with-initial-status",
			mask:    NotifyRateLimit | NotifyInitialStatus,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotifyWatchOpt(tt.mask)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("ValidateNotifyWatchOpt(%v) error = %v; wantErr %v", tt.mask, err, tt.wantErr)
			}
		})
	}
}

func TestNotifyWatchOptString(t *testing.T) {
	consts := findNotifyWatchOptConstants(t)
	t.Logf("consts = %#v", consts)

	t.Run("zero", func(t *testing.T) {
		var zero NotifyWatchOpt
		want := "ipn.NotifyWatchOpt(0x0)"
		if got := zero.String(); got != want {
			t.Errorf("NotifyWatchOpt(%#v).String() = %q, want %q", zero, got, want)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		msb := NotifyWatchOpt(1 << 63)
		want := "ipn.NotifyWatchOpt(0x8000000000000000)"
		if got := msb.String(); got != want {
			t.Errorf("NotifyWatchOpt(%#v).String() = %q, want %q", msb, got, want)
		}
	})

	t.Run("simple", func(t *testing.T) {
		for _, c := range slices.Sorted(maps.Keys(consts)) {
			if bits.OnesCount64(uint64(c)) > 1 {
				continue // multiple bits comes later
			}
			want := "ipn." + consts[c]
			if got := c.String(); got != want {
				t.Errorf("NotifyWatchOpt(%#v).String() = %q, want %q", c, got, want)
			}
		}
	})

	t.Run("composite", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value NotifyWatchOpt
			want  string
		}{
			{
				name:  "single",
				value: NotifyWatchEngineUpdates,
				want:  "ipn.NotifyWatchEngineUpdates",
			},
			{
				name:  "double",
				value: NotifyWatchEngineUpdates | NotifyInitialState,
				want:  "(ipn.NotifyWatchEngineUpdates | ipn.NotifyInitialState)",
			},
			{
				name:  "triple",
				value: NotifyWatchEngineUpdates | NotifyInitialState | NotifyInitialPrefs,
				want:  "(ipn.NotifyWatchEngineUpdates | ipn.NotifyInitialState | ipn.NotifyInitialPrefs)",
			},
			{
				name:  "unknown",
				value: NotifyWatchEngineUpdates | NotifyWatchOpt(1<<63),
				want:  "(ipn.NotifyWatchEngineUpdates | ipn.NotifyWatchOpt(0x8000000000000000))",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.value.String(); got != tc.want {
					t.Errorf("NotifyWatchOpt(%#v).String() = %q, want %q", tc.value, got, tc.want)
				}
			})
		}
	})

	// Check that every named NotifyWatchOpt value is mapped inside [NotifyWatchOpt.String].
	t.Run("all", func(t *testing.T) {
		var all NotifyWatchOpt
		var names []string // names are sorted and only contain simple consts
		for _, c := range slices.Sorted(maps.Keys(consts)) {
			all |= c
			if bits.OnesCount64(uint64(c)) == 1 {
				names = append(names, "ipn."+consts[c])
			}
		}
		want := "(" + strings.Join(names, " | ") + ")"
		if got := all.String(); got != want {
			t.Errorf("all.String() = %q, want %q", got, want)
		}
	})
}

func findNotifyWatchOptConstants(t *testing.T) map[NotifyWatchOpt]string {
	t.Helper()

	// Load the current package.
	cfg := &packages.Config{
		Mode: packages.NeedTypes,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("failed to load packages: %v", err)
	}

	// Find all the [NotifyWatchOpt] constants that represent this enum.
	var found map[NotifyWatchOpt]string
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			t.Fatalf("package %s has errors: %v", pkg.Name, pkg.Errors)
		}

		wantType := pkg.Types.Path() + ".NotifyWatchOpt"
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || obj.Type().String() != wantType {
				continue
			}
			c, ok := obj.(*types.Const)
			if !ok {
				continue
			}
			s := c.Val().ExactString()
			val, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				t.Fatalf("cannot parse %q: %v", s, err)
			}
			mak.Set(&found, NotifyWatchOpt(val), name)
		}
	}

	if len(found) == 0 {
		t.Fatal("could not find NotifyWatchOpt constants")
	}

	return found
}
