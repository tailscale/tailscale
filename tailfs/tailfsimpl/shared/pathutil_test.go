// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package shared

import (
	"reflect"
	"testing"
)

func TestCleanAndSplit(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"", []string{""}},
		{"/", []string{""}},
		{"//", []string{""}},
		{"a", []string{"a"}},
		{"/a", []string{"a"}},
		{"a/", []string{"a"}},
		{"/a/", []string{"a"}},
		{"a/b", []string{"a", "b"}},
		{"/a/b", []string{"a", "b"}},
		{"a/b/", []string{"a", "b"}},
		{"/a/b/", []string{"a", "b"}},
		{"/a/../b", []string{"b"}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := CleanAndSplit(tt.path); !reflect.DeepEqual(tt.want, got) {
				t.Errorf("CleanAndSplit(%q) = %v; want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		parts []string
		want  string
	}{
		{[]string{""}, "/"},
		{[]string{"a"}, "/a"},
		{[]string{"/a"}, "/a"},
		{[]string{"/a/"}, "/a"},
		{[]string{"/a/", "/b/"}, "/a/b"},
		{[]string{"/a/../b", "c"}, "/b/c"},
	}
	for _, tt := range tests {
		t.Run(Join(tt.parts...), func(t *testing.T) {
			if got := Join(tt.parts...); !reflect.DeepEqual(tt.want, got) {
				t.Errorf("Join(%v) = %q; want %q", tt.parts, got, tt.want)
			}
		})
	}
}
