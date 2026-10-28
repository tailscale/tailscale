// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package termwriter

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWriter(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   []string
	}{
		{
			name:   "newlines",
			chunks: []string{"a\nb\n"},
			want:   []string{"a\n\rb\n\r"},
		},
		{
			name:   "split-3-byte",
			chunks: []string{"a\xe2", "\x94\x80b"},
			want:   []string{"a", "─b"},
		},
		{
			name:   "split-4-byte-three-ways",
			chunks: []string{"\xf0", "\x9f\x98", "\x80"},
			want:   []string{"😀"},
		},
		{
			name:   "invalid-bytes-pass-through",
			chunks: []string{"a\xff", "\x80b"},
			want:   []string{"a\xff", "\x80b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			w := New(func(s string) { got = append(got, s) })
			for _, c := range tt.chunks {
				n, err := w.Write([]byte(c))
				if err != nil {
					t.Fatalf("Write: %v", err)
				}
				if n != len(c) {
					t.Fatalf("Write returned %d, want %d", n, len(c))
				}
			}

			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriterByteAtATime(t *testing.T) {
	const in = "─│ 😀\n─│"
	var got strings.Builder
	w := New(func(s string) {
		if !utf8.ValidString(s) {
			t.Errorf("wrote invalid UTF-8 %q", s)
		}
		got.WriteString(s)
	})

	for i := range len(in) {
		w.Write([]byte{in[i]})
	}

	if want := strings.ReplaceAll(in, "\n", "\n\r"); got.String() != want {
		t.Errorf("got %q, want %q", got.String(), want)
	}
}
