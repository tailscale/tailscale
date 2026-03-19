// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featuretags

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
			in:   "cli",
			want: setOf("cli"),
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

// Verify that all "ts_omit_foo" build tags are declared in featuretags.go
func TestAllOmitBuildTagsDeclared(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "..", "..")

	cmd := exec.Command("git", "grep", "ts_omit_")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skipf("git not found in PATH; skipping test")
		}
		t.Fatalf("git grep failed: %v\nOutput:\n%s", err, out)
	}
	rx := regexp.MustCompile(`\bts_omit_[\w_]+\b`)
	found := set.Set[string]{}
	rx.ReplaceAllFunc(out, func(tag []byte) []byte {
		tagStr := string(tag)
		found.Add(tagStr)
		return tag
	})
	for tag := range found {
		if strings.EqualFold(tag, "ts_omit_foo") {
			continue
		}
		ft := FeatureTag(strings.TrimPrefix(tag, "ts_omit_"))
		if _, ok := Features[ft]; !ok {
			t.Errorf("found undeclared ts_omit_* build tags: %v", tag)
		}
	}
}
