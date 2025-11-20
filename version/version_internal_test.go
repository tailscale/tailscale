// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version

import "testing"

func TestIsValidLongWithTwoRepos(t *testing.T) {
	tests := []struct {
		long string
		want bool
	}{
		{"1.2.3-t01234abcde-g01234abcde", true},
		{"1.2.259-t01234abcde-g01234abcde", true}, // big patch version
		{"1.2.3-t01234abcde", false},              // missing repo
		{"1.2.3-g01234abcde", false},              // missing repo
		{"-t01234abcde-g01234abcde", false},
		{"1.2.3", false},
		{"1.2.3-t01234abcde-g", false},
		{"1.2.3-t01234abcde-gERRBUILDINFO", false},
	}
	for _, tt := range tests {
		if got := isValidLongWithTwoRepos(tt.long); got != tt.want {
			t.Errorf("IsValidLongWithTwoRepos(%q) = %v; want %v", tt.long, got, tt.want)
		}
	}
}

func TestPrepExeNameForCmp(t *testing.T) {
	cases := []struct {
		exe  string
		want string
	}{
		{
			"tailscale-ipn.exe",
			"tailscale-ipn",
		},
		{
			"tailscale-gui-amd64.exe",
			"tailscale-gui",
		},
		{
			"tailscale-gui-amd64",
			"tailscale-gui",
		},
		{
			"tailscale-ipn",
			"tailscale-ipn",
		},
		{
			"TaIlScAlE-iPn.ExE",
			"tailscale-ipn",
		},
	}

	for _, c := range cases {
		got := prepExeNameForCmp(c.exe, "amd64")
		if got != c.want {
			t.Errorf("prepExeNameForCmp(%q) = %q; want %q", c.exe, got, c.want)
		}
	}
}
