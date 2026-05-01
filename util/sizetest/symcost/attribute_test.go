// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"testing"
)

func TestReceiverMatcher(t *testing.T) {
	tests := []struct {
		recv   string
		name   string
		want   bool
		reason string
	}{
		// Qualified receiver matched in method-receiver form.
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "tailscale.com/util/eventbus.(*Publisher[main.Event0]).Close",
			want:   true,
			reason: "pointer-receiver method on generic instantiation",
		},
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "tailscale.com/util/eventbus.(Publisher[main.Event0]).ShouldPublish",
			want:   true,
			reason: "value-receiver method on generic instantiation",
		},

		// Type descriptor short-package form.
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "*eventbus.Publisher[main.Event0]",
			want:   true,
			reason: "type descriptor uses short package name",
		},

		// Dict, eq, hash entries.
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "tailscale.com/util/eventbus..dict.Publisher[main.Event0]",
			want:   true,
			reason: "generic dictionary entry",
		},
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "type:.eq.tailscale.com/util/eventbus.Publisher[main.Event0]",
			want:   true,
			reason: "type-equality function",
		},

		// Itab entries.
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "go:itab.*tailscale.com/util/eventbus.Publisher[main.Event0],tailscale.com/util/eventbus.publisher",
			want:   true,
			reason: "itab whose concrete type is the receiver",
		},

		// Non-generic: query "main.Foo" matches "*main.Foo" (the
		// pointer-to-Foo type descriptor is what shows up in
		// .typelink for value types used in type switches).
		{
			recv:   "main.Foo",
			name:   "*main.Foo",
			want:   true,
			reason: "pointer-to-Foo descriptor",
		},
		{
			recv:   "main.Foo",
			name:   "main.Foo",
			want:   true,
			reason: "Foo descriptor itself",
		},
		{
			recv:   "main.Foo",
			name:   "type:.eq.main.Foo",
			want:   true,
			reason: "Foo equality function",
		},

		// Negative: a receiver named "Foo" must not match "FooBar".
		{
			recv:   "main.Foo",
			name:   "main.FooBar",
			want:   false,
			reason: "delimiter-aware: Foo != FooBar",
		},
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "tailscale.com/util/eventbus.publisher",
			want:   false,
			reason: "case-sensitive, Publisher != publisher",
		},
		{
			recv:   "tailscale.com/util/eventbus.Publisher",
			name:   "tailscale.com/util/eventbus.SubscriberFunc[main.Event0]",
			want:   false,
			reason: "different type with same package",
		},

		// Empty / edge cases.
		{
			recv:   "",
			name:   "anything",
			want:   false,
			reason: "empty receiver matches nothing",
		},
		{
			recv:   "main.Foo",
			name:   "",
			want:   false,
			reason: "empty name matches nothing",
		},
	}

	for _, tt := range tests {
		got := receiverMatcher(tt.recv)(tt.name)
		if got != tt.want {
			t.Errorf("receiverMatcher(%q)(%q) = %v, want %v (%s)",
				tt.recv, tt.name, got, tt.want, tt.reason)
		}
	}
}

func TestSplitLastDot(t *testing.T) {
	tests := []struct {
		in               string
		wantPkg, wantTyp string
		wantOk           bool
	}{
		{"tailscale.com/util/eventbus.Publisher", "tailscale.com/util/eventbus", "Publisher", true},
		{"main.Foo", "main", "Foo", true},
		{"justone", "", "", false},
		// Bracketed dots should not split.
		{"pkg.Foo[a.b]", "pkg", "Foo[a.b]", true},
	}
	for _, tt := range tests {
		gotPkg, gotTyp, gotOk := splitLastDot(tt.in)
		if gotPkg != tt.wantPkg || gotTyp != tt.wantTyp || gotOk != tt.wantOk {
			t.Errorf("splitLastDot(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, gotPkg, gotTyp, gotOk,
				tt.wantPkg, tt.wantTyp, tt.wantOk)
		}
	}
}
