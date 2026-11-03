// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package lineiter

import (
	"slices"
	"strings"
	"testing"
)

func TestBytesLines(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input []byte
		want  []string
	}{
		{name: "nil"},
		{name: "empty", input: []byte{}},
		{name: "single line", input: []byte("foo"), want: []string{"foo"}},
		{name: "trailing newline", input: []byte("foo\n"), want: []string{"foo"}},
		{name: "empty lines", input: []byte("\n\n"), want: []string{"", ""}},
		{name: "multiple lines", input: []byte("foo\n\nbar\nbaz"), want: []string{"foo", "", "bar", "baz"}},
		{name: "multiple trailing newlines", input: []byte("foo\nbar\n\n"), want: []string{"foo", "bar", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lines := Bytes(tt.input)
			for iteration := range 3 {
				var got []string
				for line := range lines {
					got = append(got, string(line))
				}
				if !slices.Equal(got, tt.want) {
					t.Errorf("iteration %d: got %q; want %q", iteration, got, tt.want)
				}
			}
		})
	}
}

func TestBytesLinesAfterEarlyStop(t *testing.T) {
	want := []string{"foo", "", "bar", "baz"}
	for stopAfter := 1; stopAfter <= len(want); stopAfter++ {
		lines := Bytes([]byte("foo\n\nbar\nbaz"))
		var first []string
		for line := range lines {
			first = append(first, string(line))
			if len(first) == stopAfter {
				break
			}
		}
		if !slices.Equal(first, want[:stopAfter]) {
			t.Errorf("stop after %d: got %q; want %q", stopAfter, first, want[:stopAfter])
		}

		var got []string
		for line := range lines {
			got = append(got, string(line))
		}
		if !slices.Equal(got, want) {
			t.Errorf("after stopping at %d: got %q; want %q", stopAfter, got, want)
		}
	}
}

func TestReader(t *testing.T) {
	var got []string
	for line := range Reader(strings.NewReader("foo\n\nbar\nbaz")) {
		got = append(got, string(line.MustValue()))
	}
	want := []string{"foo", "", "bar", "baz"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}
