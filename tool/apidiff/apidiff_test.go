// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestCheckCompatible(t *testing.T) {
	tests := []struct {
		name string
		new  string
		want []string
	}{
		{
			name: "compatible",
			new:  "compatible",
		},
		{
			name: "removed field",
			new:  "breaking",
			want: []string{"example.com/apidifftest/api: Response.Name: removed"},
		},
		{
			name: "removed marker",
			new:  "unmarked",
			want: []string{"example.com/apidifftest/api no longer declares packageAPIIsStable"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkCompatible(
				filepath.Join("testdata", "base"),
				filepath.Join("testdata", tt.new),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("checkCompatible() = %q, want %q", got, tt.want)
			}
		})
	}
}
