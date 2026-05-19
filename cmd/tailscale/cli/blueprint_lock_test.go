// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"

	"tailscale.com/ipn"
)

// TestCheckBlueprintSetLocked_NotBound verifies that the locked-field
// check never fires for a node that was brought up with `tailscale up`
// (i.e. Prefs.BlueprintID is empty). Existing users must be unaffected
// by the addition of Blueprints.
func TestCheckBlueprintSetLocked_NotBound(t *testing.T) {
	cur := &ipn.Prefs{}
	mp := &ipn.MaskedPrefs{AdvertiseRoutesSet: true}
	if err := checkBlueprintSetLocked(cur, mp); err != nil {
		t.Errorf("non-blueprint-bound prefs rejected: %v", err)
	}
}

// TestCheckBlueprintSetLocked_BoundNoMask verifies that a
// blueprint-bound node tolerates `tailscale set` calls that don't
// touch any locked field (e.g. setting profile name or sync state).
func TestCheckBlueprintSetLocked_BoundNoMask(t *testing.T) {
	cur := &ipn.Prefs{BlueprintID: "github-connector"}
	if err := checkBlueprintSetLocked(cur, &ipn.MaskedPrefs{ProfileNameSet: true}); err != nil {
		t.Errorf("bound prefs rejected non-locked field: %v", err)
	}
	if err := checkBlueprintSetLocked(cur, nil); err != nil {
		t.Errorf("bound prefs rejected nil maskedPrefs: %v", err)
	}
	if err := checkBlueprintSetLocked(cur, &ipn.MaskedPrefs{}); err != nil {
		t.Errorf("bound prefs rejected empty maskedPrefs: %v", err)
	}
}

// TestCheckBlueprintSetLocked_VerbatimErrorMessage verifies that the
// rejection message matches the spec exactly. This test is brittle on
// purpose: the spec prescribes the verbatim text so operators get a
// consistent, searchable error string.
func TestCheckBlueprintSetLocked_VerbatimErrorMessage(t *testing.T) {
	cur := &ipn.Prefs{BlueprintID: "github-connector"}
	mp := &ipn.MaskedPrefs{AdvertiseRoutesSet: true}
	err := checkBlueprintSetLocked(cur, mp)
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	want := "this node is bound to bp:github-connector. Routes are managed by\nthe blueprint. Edit the blueprint in the ACL to change what this node\nserves, or run 'tailscale leave' to detach."
	if got := err.Error(); got != want {
		t.Errorf("error message mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestCheckBlueprintSetLocked_AllLockedFields walks every locked
// field in the spec list and verifies that setting it on a
// blueprint-bound node returns the expected rejection.
func TestCheckBlueprintSetLocked_AllLockedFields(t *testing.T) {
	tests := []struct {
		name      string
		setMask   func(*ipn.MaskedPrefs)
		wantField string
	}{
		{
			name:      "advertise-tags",
			setMask:   func(m *ipn.MaskedPrefs) { m.AdvertiseTagsSet = true },
			wantField: "Advertised tags",
		},
		{
			name:      "advertise-routes",
			setMask:   func(m *ipn.MaskedPrefs) { m.AdvertiseRoutesSet = true },
			wantField: "Routes",
		},
		{
			name:      "advertise-connector",
			setMask:   func(m *ipn.MaskedPrefs) { m.AppConnectorSet = true },
			wantField: "App connector advertisement",
		},
		{
			name:      "ssh",
			setMask:   func(m *ipn.MaskedPrefs) { m.RunSSHSet = true },
			wantField: "SSH",
		},
		{
			name:      "accept-dns",
			setMask:   func(m *ipn.MaskedPrefs) { m.CorpDNSSet = true },
			wantField: "DNS acceptance",
		},
		{
			name:      "accept-routes",
			setMask:   func(m *ipn.MaskedPrefs) { m.RouteAllSet = true },
			wantField: "Route acceptance",
		},
	}
	cur := &ipn.Prefs{BlueprintID: "bp1"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &ipn.MaskedPrefs{}
			tt.setMask(mp)
			err := checkBlueprintSetLocked(cur, mp)
			if err == nil {
				t.Fatalf("locked field %q: expected rejection, got nil", tt.name)
			}
			if !strings.Contains(err.Error(), "this node is bound to bp:bp1") {
				t.Errorf("error missing binding name: %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantField+" are managed by") {
				t.Errorf("error missing %q field name: %v", tt.wantField, err)
			}
			if !strings.Contains(err.Error(), "tailscale leave") {
				t.Errorf("error missing leave hint: %v", err)
			}
		})
	}
}

// TestCheckBlueprintSetLocked_NodeLocalFieldsAllowed asserts the spec
// v2 narrowing: hostname, operator, shields-up, and webclient are
// node-local concerns that a blueprint has no opinion on. Setting any
// of them on a blueprint-bound node must NOT be rejected.
//
// This catches a regression where v1 (and the legacy v1.1 KB doc)
// listed these among the locked fields. Spec §11 dropped them.
func TestCheckBlueprintSetLocked_NodeLocalFieldsAllowed(t *testing.T) {
	cur := &ipn.Prefs{BlueprintID: "bp1"}
	tests := []struct {
		name    string
		setMask func(*ipn.MaskedPrefs)
	}{
		{"hostname", func(m *ipn.MaskedPrefs) { m.HostnameSet = true }},
		{"operator", func(m *ipn.MaskedPrefs) { m.OperatorUserSet = true }},
		{"shields-up", func(m *ipn.MaskedPrefs) { m.ShieldsUpSet = true }},
		{"webclient", func(m *ipn.MaskedPrefs) { m.RunWebClientSet = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &ipn.MaskedPrefs{}
			tt.setMask(mp)
			if err := checkBlueprintSetLocked(cur, mp); err != nil {
				t.Errorf("bound prefs rejected node-local field %q: %v", tt.name, err)
			}
		})
	}
}

// TestCheckBlueprintSetLocked_NilPrefs verifies that a nil curPrefs
// pointer (an unlikely but possible state during early daemon
// boot) does not panic and is treated as not-bound.
func TestCheckBlueprintSetLocked_NilPrefs(t *testing.T) {
	if err := checkBlueprintSetLocked(nil, &ipn.MaskedPrefs{AdvertiseRoutesSet: true}); err != nil {
		t.Errorf("nil curPrefs treated as bound: %v", err)
	}
}
