// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"slices"
	"testing"
	"time"
)

func TestGoTestTimeout(t *testing.T) {
	tests := []struct {
		name string
		args [][]string
		want time.Duration
	}{
		{"default", nil, defaultGoTestTimeout},
		{"eq", [][]string{{"-v", "-timeout=3m"}}, 3 * time.Minute},
		{"space", [][]string{{"-timeout", "20s", "-v"}}, 20 * time.Second},
		{"double-dash", [][]string{{"--timeout=1h"}}, time.Hour},
		{"test-prefix", [][]string{nil, {"-test.timeout=7s"}}, 7 * time.Second},
		{"zero", [][]string{{"-timeout=0"}}, 0},
		{"last-wins", [][]string{{"-timeout=1m"}, {"-timeout=2m"}}, 2 * time.Minute},
		{"invalid", [][]string{{"-timeout=bogus"}}, defaultGoTestTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goTestTimeout(tt.args...); got != tt.want {
				t.Errorf("goTestTimeout(%q) = %v; want %v", tt.args, got, tt.want)
			}
		})
	}
}

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
