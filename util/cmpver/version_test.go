// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmpver

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		name   string
		v1, v2 string
		want   int
	}{
		{
			name: "both empty",
			want: 0,
		},
		{
			name: "v1 empty",
			v2:   "1.2.3",
			want: -1,
		},
		{
			name: "v2 empty",
			v1:   "1.2.3",
			want: 1,
		},

		{
			name: "semver major",
			v1:   "2.0.0",
			v2:   "1.9.9",
			want: 1,
		},
		{
			name: "semver major",
			v1:   "2.0.0",
			v2:   "1.9.9",
			want: 1,
		},
		{
			name: "semver minor",
			v1:   "1.9.0",
			v2:   "1.8.9",
			want: 1,
		},
		{
			name: "semver patch",
			v1:   "1.9.9",
			v2:   "1.9.8",
			want: 1,
		},
		{
			name: "semver equal",
			v1:   "1.9.8",
			v2:   "1.9.8",
			want: 0,
		},

		{
			name: "tailscale major",
			v1:   "1.0-0",
			v2:   "0.97-105",
			want: 1,
		},
		{
			name: "tailscale minor",
			v1:   "0.98-0",
			v2:   "0.97-105",
			want: 1,
		},
		{
			name: "tailscale patch",
			v1:   "0.97-120",
			v2:   "0.97-105",
			want: 1,
		},
		{
			name: "tailscale equal",
			v1:   "0.97-105",
			v2:   "0.97-105",
			want: 0,
		},
		{
			name: "tailscale weird extra field",
			v1:   "0.96.1-0", // more fields == larger
			v2:   "0.96-105",
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Compare(test.v1, test.v2)
			if got != test.want {
				t.Errorf("Compare(%v, %v) = %v, want %v", test.v1, test.v2, got, test.want)
			}
			// Reversing the comparison should reverse the outcome.
			got2 := Compare(test.v2, test.v1)
			if got2 != -test.want {
				t.Errorf("Compare(%v, %v) = %v, want %v", test.v2, test.v1, got2, -test.want)
			}
		})
	}
}
