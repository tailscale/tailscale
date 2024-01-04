// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"slices"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name            string
		in              []string
		pre, pkgs, post []string
	}{
		{
			name: "empty",
		},
		{
			name: "all",
			in:   []string{"-v", "pkg1", "pkg2", "-run", "TestFoo", "-timeout=20s"},
			pre:  []string{"-v"},
			pkgs: []string{"pkg1", "pkg2"},
			post: []string{"-run", "TestFoo", "-timeout=20s"},
		},
		{
			name: "only_pkgs",
			in:   []string{"./..."},
			pkgs: []string{"./..."},
		},
		{
			name: "pkgs_and_post",
			in:   []string{"pkg1", "-run", "TestFoo"},
			pkgs: []string{"pkg1"},
			post: []string{"-run", "TestFoo"},
		},
		{
			name: "pkgs_and_post",
			in:   []string{"-v", "pkg2"},
			pre:  []string{"-v"},
			pkgs: []string{"pkg2"},
		},
		{
			name: "only_args",
			in:   []string{"-v", "-run=TestFoo"},
			pre:  []string{"-run", "TestFoo", "-v"}, // sorted
		},
		{
			name: "space_in_pre_arg",
			in:   []string{"-run", "TestFoo", "./cmd/testwrapper"},
			pre:  []string{"-run", "TestFoo"},
			pkgs: []string{"./cmd/testwrapper"},
		},
		{
			name: "space_in_arg",
			in:   []string{"-exec", "sudo -E", "./cmd/testwrapper"},
			pre:  []string{"-exec", "sudo -E"},
			pkgs: []string{"./cmd/testwrapper"},
		},
		{
			name: "test-arg",
			in:   []string{"-exec", "sudo -E", "./cmd/testwrapper", "--", "--some-flag"},
			pre:  []string{"-exec", "sudo -E"},
			pkgs: []string{"./cmd/testwrapper"},
			post: []string{"--", "--some-flag"},
		},
		{
			name: "dupe-args",
			in:   []string{"-v", "-v", "-race", "-race", "./cmd/testwrapper", "--", "--some-flag"},
			pre:  []string{"-race", "-v"},
			pkgs: []string{"./cmd/testwrapper"},
			post: []string{"--", "--some-flag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pre, pkgs, post, err := splitArgs(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pre, tt.pre) {
				t.Errorf("pre = %q; want %q", pre, tt.pre)
			}
			if !slices.Equal(pkgs, tt.pkgs) {
				t.Errorf("pattern = %q; want %q", pkgs, tt.pkgs)
			}
			if !slices.Equal(post, tt.post) {
				t.Errorf("post = %q; want %q", post, tt.post)
			}
			if t.Failed() {
				t.Logf("SplitArgs(%q) = %q %q %q", tt.in, pre, pkgs, post)
			}
		})
	}
}
