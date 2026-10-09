// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnstate_test

import (
	jsonv1 "encoding/json"
	"net/netip"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestPeerStatusIsRouter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status ipnstate.PeerStatus
		want   bool
	}{
		{
			name:   "empty",
			status: ipnstate.PeerStatus{},
			want:   false,
		},
		{
			name: "invalid",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{}),
			},
			want: false,
		},
		{
			name: "plain-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				}),
			},
			want: false,
		},
		{
			name: "plain-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				}),
			},
			want: false,
		},
		{
			name: "plain-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				}),
			},
			want: false,
		},
		{
			name: "exit-node-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("0.0.0.0/0"),
				}),
			},
			want: true,
		},
		{
			name: "exit-node-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("::/0"),
				}),
			},
			want: true,
		},
		{
			name: "exit-node-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				}),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("192.0.2.0/24"),
				}),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("2001:db8::/32"),
				}),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("192.0.2.0/24"),
					netip.MustParsePrefix("2001:db8::/32"),
				}),
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.status.IsRouter(); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

// TestPeerStatusSliceViewFieldsJSON verifies the JSON encoding contract of the
// views.Slice fields on the real PeerStatus type (AllowedIPs, Tags,
// PrimaryRoutes) under both encoders the views types support: encoding/json
// (jsonv1) and go-json-experiment/json (jsonv2).
//
// These fields were previously *views.Slice with json:",omitempty" and are now
// views.Slice with json:",omitzero". This is the wire-format contract: these
// fields are serialized over the LocalAPI and decoded by consumers (the web
// client, tsnet, containerboot, k8s-operator, etc.) that are decoupled from
// this type by JSON, so the observable encoding must not change.
//
// The contract, for each field:
//   - a zero (unset/nil) view => key omitted entirely
//   - a populated view        => key present with a JSON array
//
// It marshals the real PeerStatus and inspects only these three keys (via a map
// decode) so the assertion is robust to the dozens of unrelated PeerStatus
// fields. See TestPeerStatusSliceViewFieldsJSONMatchesPointerShape for the
// proof that this matches the previous *views.Slice representation byte-for-byte.
func TestPeerStatusSliceViewFieldsJSON(t *testing.T) {
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	const (
		allowed = "AllowedIPs"
		tags    = "Tags"
		routes  = "PrimaryRoutes"
	)

	tests := []struct {
		name string
		ps   ipnstate.PeerStatus
		// want maps each of the three keys to its expected raw JSON value, or
		// omits the key entirely to assert it is absent from the output.
		want map[string]string
	}{
		{
			name: "all-unset",
			ps:   ipnstate.PeerStatus{},
			want: map[string]string{}, // all three keys absent
		},
		{
			name: "allowed-ips",
			ps:   ipnstate.PeerStatus{AllowedIPs: views.SliceOf([]netip.Prefix{pfx("100.64.0.1/32"), pfx("0.0.0.0/0")})},
			want: map[string]string{allowed: `["100.64.0.1/32","0.0.0.0/0"]`},
		},
		{
			name: "tags",
			ps:   ipnstate.PeerStatus{Tags: views.SliceOf([]string{"tag:server", "tag:prod"})},
			want: map[string]string{tags: `["tag:server","tag:prod"]`},
		},
		{
			name: "primary-routes",
			ps:   ipnstate.PeerStatus{PrimaryRoutes: views.SliceOf([]netip.Prefix{pfx("10.0.0.0/24")})},
			want: map[string]string{routes: `["10.0.0.0/24"]`},
		},
		{
			name: "all-populated",
			ps: ipnstate.PeerStatus{
				AllowedIPs:    views.SliceOf([]netip.Prefix{pfx("100.64.0.1/32")}),
				Tags:          views.SliceOf([]string{"tag:server"}),
				PrimaryRoutes: views.SliceOf([]netip.Prefix{pfx("10.0.0.0/24")}),
			},
			want: map[string]string{
				allowed: `["100.64.0.1/32"]`,
				tags:    `["tag:server"]`,
				routes:  `["10.0.0.0/24"]`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, enc := range []struct {
				name string
				fn   func(any) ([]byte, error)
			}{
				{"encoding/json", jsonv1.Marshal},
				{"go-json-experiment/json", func(v any) ([]byte, error) { return jsonv2.Marshal(v) }},
			} {
				b, err := enc.fn(tt.ps)
				if err != nil {
					t.Fatalf("%s: marshal: %v", enc.name, err)
				}
				var obj map[string]jsonv1.RawMessage
				if err := jsonv1.Unmarshal(b, &obj); err != nil {
					t.Fatalf("%s: unmarshal to map: %v", enc.name, err)
				}
				for _, key := range []string{allowed, tags, routes} {
					got, present := obj[key]
					wantVal, wantPresent := tt.want[key]
					if present != wantPresent {
						t.Errorf("%s: key %q present=%v, want %v (full: %s)", enc.name, key, present, wantPresent, b)
						continue
					}
					if wantPresent && string(got) != wantVal {
						t.Errorf("%s: key %q = %s, want %s", enc.name, key, got, wantVal)
					}
				}
			}
		})
	}
}

// TestPeerStatusSliceViewFieldsJSONMatchesPointerShape proves that the current
// value-typed views.Slice fields with json:",omitzero" encode byte-for-byte
// identically to the previous *views.Slice fields with json:",omitempty",
// under both encoders. This is the core wire-compatibility guarantee of the
// pointer->value migration.
//
// Empty-but-non-nil views are intentionally excluded: producers must never
// populate these fields with an empty, non-nil view (peerStatusFromNode guards
// on Len()!=0), which is exactly the state where the two shapes would diverge.
func TestPeerStatusSliceViewFieldsJSONMatchesPointerShape(t *testing.T) {
	type newFields struct {
		AllowedIPs    views.Slice[netip.Prefix] `json:",omitzero"`
		Tags          views.Slice[string]       `json:",omitzero"`
		PrimaryRoutes views.Slice[netip.Prefix] `json:",omitzero"`
	}
	type oldFields struct {
		AllowedIPs    *views.Slice[netip.Prefix] `json:",omitempty"`
		Tags          *views.Slice[string]       `json:",omitempty"`
		PrimaryRoutes *views.Slice[netip.Prefix] `json:",omitempty"`
	}
	ptr := func(v views.Slice[netip.Prefix]) *views.Slice[netip.Prefix] { return &v }
	ptrS := func(v views.Slice[string]) *views.Slice[string] { return &v }
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }

	aips := views.SliceOf([]netip.Prefix{pfx("100.64.0.1/32"), pfx("0.0.0.0/0")})
	tg := views.SliceOf([]string{"tag:server"})
	rt := views.SliceOf([]netip.Prefix{pfx("10.0.0.0/24")})

	tests := []struct {
		name string
		new  newFields
		old  oldFields
	}{
		{"all-unset", newFields{}, oldFields{}},
		{
			"all-populated",
			newFields{AllowedIPs: aips, Tags: tg, PrimaryRoutes: rt},
			oldFields{AllowedIPs: ptr(aips), Tags: ptrS(tg), PrimaryRoutes: ptr(rt)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, enc := range []struct {
				name string
				fn   func(any) ([]byte, error)
			}{
				{"encoding/json", jsonv1.Marshal},
				{"go-json-experiment/json", func(v any) ([]byte, error) { return jsonv2.Marshal(v) }},
			} {
				gotNew, err := enc.fn(tt.new)
				if err != nil {
					t.Fatalf("%s new: %v", enc.name, err)
				}
				gotOld, err := enc.fn(tt.old)
				if err != nil {
					t.Fatalf("%s old: %v", enc.name, err)
				}
				if string(gotNew) != string(gotOld) {
					t.Errorf("%s: value shape diverged from pointer shape:\n old=%s\n new=%s", enc.name, gotOld, gotNew)
				}
			}
		})
	}
}

// TestPeerStatusSliceViewFieldsJSONBackCompat verifies that PeerStatus decodes
// JSON produced by the previous (*views.Slice with omitempty) representation.
// A peer produced by an older node may include the field as null (the zero
// value a *views.Slice with omitempty could emit when the pointer was non-nil
// but the underlying slice was nil), or omit it, or include a populated array.
// All must decode without error and yield an iterable (never-panicking) view.
func TestPeerStatusSliceViewFieldsJSONBackCompat(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantLen int
	}{
		{"field-absent", `{"ID":"n1"}`, 0},
		{"field-null", `{"ID":"n1","AllowedIPs":null}`, 0},
		{"field-empty-array", `{"ID":"n1","AllowedIPs":[]}`, 0},
		{"field-populated", `{"ID":"n1","AllowedIPs":["100.64.0.1/32"]}`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, dec := range []struct {
				name string
				fn   func([]byte, any) error
			}{
				{"encoding/json", jsonv1.Unmarshal},
				{"go-json-experiment/json", func(b []byte, v any) error { return jsonv2.Unmarshal(b, v) }},
			} {
				var ps ipnstate.PeerStatus
				if err := dec.fn([]byte(tt.in), &ps); err != nil {
					t.Fatalf("%s: unmarshal: %v", dec.name, err)
				}
				if got := ps.AllowedIPs.Len(); got != tt.wantLen {
					t.Errorf("%s: AllowedIPs.Len() = %d, want %d", dec.name, got, tt.wantLen)
				}
				// Must be iterable regardless of how it was decoded.
				n := 0
				for range ps.AllowedIPs.All() {
					n++
				}
				if n != tt.wantLen {
					t.Errorf("%s: iterated %d, want %d", dec.name, n, tt.wantLen)
				}
			}
		})
	}
}
