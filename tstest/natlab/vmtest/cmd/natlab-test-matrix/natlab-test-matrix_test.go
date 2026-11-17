// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"slices"
	"testing"

	"tailscale.com/tstest"
)

func TestGenerateTree(t *testing.T) {
	tstest.Replace(t, &VariationMap, map[string][]string{
		"vmtest.OSImage": {
			"vmtest.Gokrazy",
			"vmtest.Ubuntu2404",
			"vmtest.Debian12",
		},
	})

	tests := []struct {
		name          string
		inputSelected []string
		inputParams   []string
		want          [][]string
	}{
		{
			name:          "single_param",
			inputSelected: []string{},
			inputParams:   []string{"vmtest.OSImage"},
			want: [][]string{
				{"vmtest.Gokrazy"},
				{"vmtest.Ubuntu2404"},
				{"vmtest.Debian12"},
			},
		},
		{
			name:          "dual_param",
			inputSelected: []string{},
			inputParams:   []string{"vmtest.OSImage", "vmtest.OSImage"},
			want: [][]string{
				{"vmtest.Gokrazy", "vmtest.Gokrazy"},
				{"vmtest.Gokrazy", "vmtest.Ubuntu2404"},
				{"vmtest.Gokrazy", "vmtest.Debian12"},
				{"vmtest.Ubuntu2404", "vmtest.Gokrazy"},
				{"vmtest.Ubuntu2404", "vmtest.Ubuntu2404"},
				{"vmtest.Ubuntu2404", "vmtest.Debian12"},
				{"vmtest.Debian12", "vmtest.Gokrazy"},
				{"vmtest.Debian12", "vmtest.Ubuntu2404"},
				{"vmtest.Debian12", "vmtest.Debian12"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateTree(tt.inputSelected, tt.inputParams)
			if len(got) != len(tt.want) {
				t.Fatalf("wrong response length, +got len(%d), -want len(%d)\ngot: %+v\nwant: %+v",
					len(got), len(tt.want), got, tt.want)
			}
			for i, test := range got {
				if slices.Compare(test, tt.want[i]) != 0 {
					t.Errorf("bad param response, +got %v, -want %v", test, tt.want[i])
				}
			}
		})
	}
}
