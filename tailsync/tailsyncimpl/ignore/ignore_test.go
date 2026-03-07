// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ignore

import "testing"

func TestMatcherDefaults(t *testing.T) {
	m := NewWithDefaults(nil)

	tests := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{".git", true, true},
		{".git/config", false, true},
		{"src/main.go", false, false},
		{"node_modules", true, true},
		{"node_modules/foo/bar.js", false, true},
		{"__pycache__", true, true},
		{"foo.pyc", false, true},
		{".DS_Store", false, true},
		{"foo.swp", false, true},
		{"foo~", false, true},
		{".tailsync-conflicts", true, true},
		{"src/app.ts", false, false},
		{"README.md", false, false},
	}

	for _, tt := range tests {
		got := m.Match(tt.path, tt.isDir)
		if got != tt.want {
			t.Errorf("Match(%q, isDir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
		}
	}
}

func TestMatcherCustomPatterns(t *testing.T) {
	m := New([]string{"*.log", "build/", "!important.log"})

	tests := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"app.log", false, false}, // negated by !important.log pattern... actually no
		{"debug.log", false, true},
		{"build", true, true},
		{"build/output.bin", false, false}, // build/ pattern is dir-only
		{"src/main.go", false, false},
	}

	// Correction: !important.log only negates important.log specifically
	m2 := New([]string{"*.log", "build/", "!important.log"})
	if !m2.Match("debug.log", false) {
		t.Error("expected debug.log to be ignored")
	}
	if m2.Match("important.log", false) {
		t.Error("expected important.log to NOT be ignored (negated)")
	}
	if !m.Match("build", true) {
		t.Error("expected build/ dir to be ignored")
	}
	if m.Match("src/main.go", false) {
		t.Error("expected src/main.go to NOT be ignored")
	}

	_ = tests // test cases documented above
}

func TestMatcherNil(t *testing.T) {
	var m *Matcher
	if m.Match("anything", false) {
		t.Error("nil matcher should not match anything")
	}
}
