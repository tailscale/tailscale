// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	"slices"
	"testing"
)

func TestPortRangesAll(t *testing.T) {
	tests := []struct {
		name string
		prs  PortRanges
		want []uint16
	}{
		{
			name: "single_port",
			prs:  PortRanges{{Port: 30000}},
			want: []uint16{30000},
		},
		{
			name: "small_range",
			prs:  PortRanges{{Port: 30000, EndPort: 30002}},
			want: []uint16{30000, 30001, 30002},
		},
		{
			name: "range_ending_at_max_port",
			prs:  PortRanges{{Port: 65533, EndPort: 65535}},
			want: []uint16{65533, 65534, 65535},
		},
		{
			name: "single_max_port",
			prs:  PortRanges{{Port: 65535}},
			want: []uint16{65535},
		},
		{
			name: "multiple_ranges",
			prs:  PortRanges{{Port: 30000, EndPort: 30001}, {Port: 65535}},
			want: []uint16{30000, 30001, 65535},
		},
		{
			name: "inverted_range_yields_nothing",
			prs:  PortRanges{{Port: 30100, EndPort: 30000}},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint16
			for p := range tt.prs.All() {
				got = append(got, p)
				if len(got) > len(tt.want) {
					t.Fatalf("All() yielded more than the %d expected ports; got %v...", len(tt.want), got)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("All() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortRangesClashesWith(t *testing.T) {
	tests := []struct {
		name string
		prs  PortRanges
		pr   PortRange
		want bool
	}{
		{
			name: "overlapping",
			prs:  PortRanges{{Port: 30000, EndPort: 30100}},
			pr:   PortRange{Port: 30050, EndPort: 30150},
			want: true,
		},
		{
			name: "disjoint",
			prs:  PortRanges{{Port: 30000, EndPort: 30100}},
			pr:   PortRange{Port: 30101, EndPort: 30200},
			want: false,
		},
		{
			name: "disjoint_below_range_ending_at_max_port",
			prs:  PortRanges{{Port: 40000, EndPort: 65535}},
			pr:   PortRange{Port: 30000, EndPort: 30100},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.prs.ClashesWith(tt.pr); got != tt.want {
				t.Errorf("ClashesWith(%s) = %v, want %v", tt.pr, got, tt.want)
			}
		})
	}
}
