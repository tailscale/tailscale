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

func TestResolverHostname(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"https://coredns.foo.ts.net:8443/dns-query", "coredns.foo.ts.net"},
		{"https://coredns.foo.ts.net/dns-query", "coredns.foo.ts.net"},
		{"http://100.64.0.5:8053/dns-query", "100.64.0.5"},
		{"http://[fd7a:115c:a1e0::abcd]:8053", "fd7a:115c:a1e0::abcd"},
		{"tls://dns.example.com:853", "dns.example.com"},
		{"100.64.0.5:53", "100.64.0.5"},
		// Embedded-v4 form is canonicalized by netip.ParseAddr to plain hex; that's fine for our callers (they re-parse the result, not string-compare it).
		{"[fd7a:115c:a1e0:b1a:0:1:1.2.3.4]:53", "fd7a:115c:a1e0:b1a:0:1:102:304"},
		{"8.8.8.8:53", "8.8.8.8"},
		// Bare IPs without a port (the common control-plane format).
		{"100.64.0.5", "100.64.0.5"},
		{"8.8.8.8", "8.8.8.8"},
		{"fd7a:115c:a1e0::abcd", "fd7a:115c:a1e0::abcd"},
		{"2001:db8::1", "2001:db8::1"},
		// Malformed / empty / unsupported forms.
		{"https://[invalid", ""},
		{"not a url", ""},
		{"corp-resolver.example.com", ""}, // bare hostname, no scheme or port: not a supported Resolver.Addr form
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			r := &Resolver{Addr: tt.addr}
			if got := r.Hostname(); got != tt.want {
				t.Errorf("Hostname(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
