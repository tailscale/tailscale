// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package example

import "testing"

func TestDirect(t *testing.T) {
	// Bad: spaces
	t.Run("that everything's cool", func(t *testing.T) {}) // want `subtest name "that everything's cool" contains characters that require quoting`

	// Bad: apostrophe
	t.Run("it's working", func(t *testing.T) {}) // want `subtest name "it's working" contains characters that require quoting`

	// Bad: regex metacharacters
	t.Run("test(foo)", func(t *testing.T) {}) // want `subtest name "test\(foo\)" contains characters that require quoting`
	t.Run("test[0]", func(t *testing.T) {})   // want `subtest name "test\[0\]" contains characters that require quoting`
	t.Run("a|b", func(t *testing.T) {})       // want `subtest name "a\|b" contains characters that require quoting`
	t.Run("a*b", func(t *testing.T) {})       // want `subtest name "a\*b" contains characters that require quoting`
	t.Run("a+b", func(t *testing.T) {})       // want `subtest name "a\+b" contains characters that require quoting`
	t.Run("a.b", func(t *testing.T) {})       // want `subtest name "a\.b" contains characters that require quoting`
	t.Run("^start", func(t *testing.T) {})    // want `subtest name "\^start" contains characters that require quoting`
	t.Run("end$", func(t *testing.T) {})      // want `subtest name "end\$" contains characters that require quoting`
	t.Run("a{2}", func(t *testing.T) {})      // want `subtest name "a\{2\}" contains characters that require quoting`
	t.Run("a?b", func(t *testing.T) {})       // want `subtest name "a\?b" contains characters that require quoting`
	t.Run("a\\b", func(t *testing.T) {})      // want `subtest name "a\\\\b" contains characters that require quoting`

	// Bad: double quotes
	t.Run("say \"hello\"", func(t *testing.T) {}) // want `subtest name "say \\"hello\\"" contains characters that require quoting`

	// Bad: hash
	t.Run("comment#1", func(t *testing.T) {}) // want `subtest name "comment#1" contains characters that require quoting`

	// Bad: leading/trailing dash
	t.Run("-leading-dash", func(t *testing.T) {})  // want `subtest name "-leading-dash" starts or ends with '-' which is problematic`
	t.Run("trailing-dash-", func(t *testing.T) {}) // want `subtest name "trailing-dash-" starts or ends with '-' which is problematic`
	t.Run("-both-", func(t *testing.T) {})         // want `subtest name "-both-" starts or ends with '-' which is problematic`

	// Good: clean names
	t.Run("zero-passes", func(t *testing.T) {})
	t.Run("simple_test", func(t *testing.T) {})
	t.Run("CamelCase", func(t *testing.T) {})
	t.Run("with-dashes", func(t *testing.T) {})
	t.Run("123", func(t *testing.T) {})
	t.Run("comma,separated", func(t *testing.T) {})
	t.Run("colon:value", func(t *testing.T) {})
	t.Run("slash/path", func(t *testing.T) {})
	t.Run("equals=sign", func(t *testing.T) {})
}

func TestTableDriven(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{name: "bad space name", val: 1}, // want `subtest name "bad space name" contains characters that require quoting`
		{name: "good-name", val: 2},
		{name: "also(bad)", val: 3}, // want `subtest name "also\(bad\)" contains characters that require quoting`
		{name: "it's-bad", val: 4},  // want `subtest name "it's-bad" contains characters that require quoting`
		{name: "clean-name", val: 5},
		{name: "-leading-dash", val: 6}, // want `subtest name "-leading-dash" starts or ends with '-' which is problematic`
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {})
	}
}

func TestTableDrivenVar(t *testing.T) {
	var tests = []struct {
		name string
		val  int
	}{
		{name: "has spaces", val: 1}, // want `subtest name "has spaces" contains characters that require quoting`
		{name: "ok-name", val: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {})
	}
}

func TestTableDrivenMap(t *testing.T) {
	tests := map[string]struct {
		name string
		val  int
	}{
		"key1": {name: "bad name here", val: 1}, // want `subtest name "bad name here" contains characters that require quoting`
		"key2": {name: "ok-name", val: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {})
	}
}

func TestNotTesting(t *testing.T) {
	// Not a t.Run call, should not trigger.
	s := struct{ Run func(string, func()) }{}
	s.Run("bad name here", func() {})
}

func TestDynamicName(t *testing.T) {
	// Dynamic name, not a string literal — should not trigger.
	name := getName()
	t.Run(name, func(t *testing.T) {})
}

func getName() string { return "foo" }

func BenchmarkDirect(b *testing.B) {
	// Also check b.Run.
	b.Run("bad name here", func(b *testing.B) {}) // want `subtest name "bad name here" contains characters that require quoting`
	b.Run("good-name", func(b *testing.B) {})
}
