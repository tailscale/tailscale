// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cmpver_test

import (
	"testing"

	"tailscale.com/util/cmpver"
)

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
		{
			// Though ۱ and ۲ both satisfy unicode.IsNumber, our previous use
			// of strconv.ParseUint with these characters would have lead us to
			// panic. We're now only looking at ascii numbers, so test these are
			// compared as text.
			name: "only ascii numbers",
			v1:   "۱۱", // 2x EXTENDED ARABIC-INDIC DIGIT ONE
			v2:   "۲",  // 1x EXTENDED ARABIC-INDIC DIGIT TWO
			want: -1,
		},

		// A few specific OS version tests below.
		{
			name: "windows version",
			v1:   "10.0.19045.3324",
			v2:   "10.0.18362",
			want: 1,
		},
		{
			name: "windows 11 is everything above 10.0.22000",
			v1:   "10.0.22631.2262",
			v2:   "10.0.22000",
			want: 1,
		},
		{
			name: "android short version",
			v1:   "10",
			v2:   "7",
			want: 1,
		},
		{
			name: "android longer version",
			v1:   "7.1.2",
			v2:   "7",
			want: 1,
		},
		{
			name: "iOS version",
			v1:   "15.6.1",
			v2:   "15.6",
			want: 1,
		},
		{
			name: "Linux short kernel version",
			v1:   "4.4.302+",
			v2:   "4.0",
			want: 1,
		},
		{
			name: "Linux long kernel version",
			v1:   "4.14.255-311-248.529.amzn2.x86_64",
			v2:   "4.0",
			want: 1,
		},
		{
			name: "FreeBSD version",
			v1:   "14.0-CURRENT",
			v2:   "14",
			want: 1,
		},
		{
			name: "Synology version",
			v1:   "Synology 6.2.4; kernel=3.10.105",
			v2:   "Synology 6",
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := cmpver.Compare(test.v1, test.v2)
			if got != test.want {
				t.Errorf("Compare(%q, %q) = %v, want %v", test.v1, test.v2, got, test.want)
			}

			// Reversing the comparison should reverse the outcome.
			got2 := cmpver.Compare(test.v2, test.v1)
			if got2 != -test.want {
				t.Errorf("Compare(%q, %q) = %v, want %v", test.v2, test.v1, got2, -test.want)
			}

			if got, want := cmpver.Less(test.v1, test.v2), test.want < 0; got != want {
				t.Errorf("Less(%q, %q) = %v, want %v", test.v1, test.v2, got, want)
			}
			if got, want := cmpver.Less(test.v2, test.v1), test.want > 0; got != want {
				t.Errorf("Less(%q, %q) = %v, want %v", test.v2, test.v1, got, want)
			}
			if got, want := cmpver.LessEq(test.v1, test.v2), test.want <= 0; got != want {
				t.Errorf("LessEq(%q, %q) = %v, want %v", test.v1, test.v2, got, want)
			}
			if got, want := cmpver.LessEq(test.v2, test.v1), test.want >= 0; got != want {
				t.Errorf("LessEq(%q, %q) = %v, want %v", test.v2, test.v1, got, want)
			}

			// Check that version comparison does not allocate.
			if n := testing.AllocsPerRun(100, func() { cmpver.Compare(test.v1, test.v2) }); n > 0 {
				t.Errorf("Compare(%q, %q) got %v allocs per run", test.v1, test.v2, n)
			}
		})
	}
}
