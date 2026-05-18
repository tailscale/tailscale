// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnstype

import (
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"testing"
)

func TestResolverEqual(t *testing.T) {
	var fieldNames []string
	for _, field := range reflect.VisibleFields(reflect.TypeFor[Resolver]()) {
		fieldNames = append(fieldNames, field.Name)
	}
	sort.Strings(fieldNames)
	if !slices.Equal(fieldNames, []string{"Addr", "BootstrapResolution", "UseWithExitNode"}) {
		t.Errorf("Resolver fields changed; update test")
	}

	tests := []struct {
		name string
		a, b *Resolver
		want bool
	}{
		{
			name: "nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "nil-vs-non-nil",
			a:    nil,
			b:    &Resolver{},
			want: false,
		},
		{
			name: "non-nil-vs-nil",
			a:    &Resolver{},
			b:    nil,
			want: false,
		},
		{
			name: "equal",
			a:    &Resolver{Addr: "dns.example.com"},
			b:    &Resolver{Addr: "dns.example.com"},
			want: true,
		},
		{
			name: "not-equal-addrs",
			a:    &Resolver{Addr: "dns.example.com"},
			b:    &Resolver{Addr: "dns2.example.com"},
			want: false,
		},
		{
			name: "not-equal-bootstrap",
			a: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			},
			b: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: []netip.Addr{netip.MustParseAddr("8.8.4.4")},
			},
			want: false,
		},
		{
			// nil and an explicitly-empty slice are distinct on the wire:
			// nil means "fall back to the client's own resolution" while
			// an empty list means "skip the client's static-IP fallback".
			name: "not-equal-bootstrap-nil-vs-empty",
			a: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: nil,
			},
			b: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: []netip.Addr{},
			},
			want: false,
		},
		{
			name: "equal-bootstrap-both-empty",
			a: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: []netip.Addr{},
			},
			b: &Resolver{
				Addr:                "dns.example.com",
				BootstrapResolution: []netip.Addr{},
			},
			want: true,
		},
		{
			name: "equal-UseWithExitNode",
			a:    &Resolver{Addr: "dns.example.com", UseWithExitNode: true},
			b:    &Resolver{Addr: "dns.example.com", UseWithExitNode: true},
			want: true,
		},
		{
			name: "not-equal-UseWithExitNode",
			a:    &Resolver{Addr: "dns.example.com", UseWithExitNode: true},
			b:    &Resolver{Addr: "dns.example.com", UseWithExitNode: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Equal(tt.b)
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}
