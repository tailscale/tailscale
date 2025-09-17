// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package featuretags

import (
	"maps"
	"slices"
	"testing"

	"tailscale.com/util/set"
)

func TestKnownDeps(t *testing.T) {
	for tag, meta := range Features {
		for _, dep := range meta.Deps {
			if _, ok := Features[dep]; !ok {
				t.Errorf("feature %q has unknown dependency %q", tag, dep)
			}
		}

		// And indirectly check for cycles. If there were a cycle,
		// this would infinitely loop.
		deps := Requires(tag)
		t.Logf("deps of %q: %v", tag, slices.Sorted(maps.Keys(deps)))
	}
}

func TestRequires(t *testing.T) {
	var setOf = set.Of[FeatureTag]
	tests := []struct {
		in   FeatureTag
		want set.Set[FeatureTag]
	}{
		{
			in:   "drive",
			want: setOf("drive"),
		},
		{
			in:   "serve",
			want: setOf("serve", "netstack"),
		},
		{
			in:   "webclient",
			want: setOf("webclient", "serve", "netstack"),
		},
	}
	for _, tt := range tests {
		got := Requires(tt.in)
		if !maps.Equal(got, tt.want) {
			t.Errorf("DepSet(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRequiredBy(t *testing.T) {
	var setOf = set.Of[FeatureTag]
	tests := []struct {
		in   FeatureTag
		want set.Set[FeatureTag]
	}{
		{
			in:   "drive",
			want: setOf("drive"),
		},
		{
			in:   "webclient",
			want: setOf("webclient"),
		},
		{
			in:   "serve",
			want: setOf("webclient", "serve"),
		},
	}
	for _, tt := range tests {
		got := RequiredBy(tt.in)
		if !maps.Equal(got, tt.want) {
			t.Errorf("FeaturesWhichDependOn(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
