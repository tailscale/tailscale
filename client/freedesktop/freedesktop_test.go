// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package freedesktop

import (
	"strings"
	"testing"
)

func TestEscape(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{
			name:  "no illegal chars",
			input: "/home/user",
			want:  "/home/user",
		},
		{
			name:  "empty string",
			input: "",
			want:  "\"\"",
		},
		{
			name:  "space",
			input: " ",
			want:  "\" \"",
		},
		{
			name:  "tab",
			input: "\t",
			want:  "\"\t\"",
		},
		{
			name:  "newline",
			input: "\n",
			want:  "\"\n\"",
		},
		{
			name:  "double quote",
			input: "\"",
			want:  "\"\\\"\"",
		},
		{
			name:  "single quote",
			input: "'",
			want:  "\"'\"",
		},
		{
			name:  "backslash",
			input: "\\",
			want:  "\"\\\\\"",
		},
		{
			name:  "greater than",
			input: ">",
			want:  "\">\"",
		},
		{
			name:  "less than",
			input: "<",
			want:  "\"<\"",
		},
		{
			name:  "tilde",
			input: "~",
			want:  "\"~\"",
		},
		{
			name:  "pipe",
			input: "|",
			want:  "\"|\"",
		},
		{
			name:  "ampersand",
			input: "&",
			want:  "\"&\"",
		},
		{
			name:  "semicolon",
			input: ";",
			want:  "\";\"",
		},
		{
			name:  "dollar",
			input: "$",
			want:  "\"\\$\"",
		},
		{
			name:  "asterisk",
			input: "*",
			want:  "\"*\"",
		},
		{
			name:  "question mark",
			input: "?",
			want:  "\"?\"",
		},
		{
			name:  "hash",
			input: "#",
			want:  "\"#\"",
		},
		{
			name:  "open paren",
			input: "(",
			want:  "\"(\"",
		},
		{
			name:  "close paren",
			input: ")",
			want:  "\")\"",
		},
		{
			name:  "backtick",
			input: "`",
			want:  "\"\\`\"",
		},
		{
			name:  "char without escape",
			input: "/home/user\t",
			want:  "\"/home/user\t\"",
		},
		{
			name:  "char with escape",
			input: "/home/user\\",
			want:  "\"/home/user\\\\\"",
		},
		{
			name:  "all illegal chars",
			input: "/home/user" + needsEscape,
			want:  "\"/home/user \t\n\\\"'\\\\><~|&;\\$*?#()\\`\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Quote(tt.input)
			if strings.Compare(got, tt.want) != 0 {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}
