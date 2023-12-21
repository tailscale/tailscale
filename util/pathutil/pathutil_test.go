// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pathutil

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
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
			if got := Split(tt.path); !reflect.DeepEqual(tt.want, got) {
				t.Errorf("Split(%q) = %v; want %v", tt.path, got, tt.want)
			}
		})
	}

}
