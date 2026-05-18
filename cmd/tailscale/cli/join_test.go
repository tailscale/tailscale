// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"
)

func TestResolveBlueprintArg(t *testing.T) {
	tests := []struct {
		name       string
		positional string
		flagVal    string
		wantID     string
		wantErr    string
	}{
		// All four equivalent forms from the spec must yield the same id.
		{"flag_prefixed", "", "bp:foo", "foo", ""},
		{"flag_bare", "", "foo", "foo", ""},
		{"positional_prefixed", "bp:foo", "", "foo", ""},
		{"positional_bare", "foo", "", "foo", ""},

		// Both forms agree (same id after normalization) -> accept silently.
		{"both_agree_prefixed_prefixed", "bp:foo", "bp:foo", "foo", ""},
		{"both_agree_bare_prefixed", "foo", "bp:foo", "foo", ""},
		{"both_agree_prefixed_bare", "bp:foo", "foo", "foo", ""},
		{"both_agree_bare_bare", "foo", "foo", "foo", ""},

		// Mismatched forms.
		{
			name:       "mismatch_both_prefixed",
			positional: "bp:foo",
			flagVal:    "bp:bar",
			wantErr:    "blueprint specified twice: 'bp:foo' (positional) and 'bp:bar' (--blueprint). Pass one or the other",
		},
		{
			// The error should report the normalized "bp:<id>" form
			// regardless of whether the user wrote the bare or prefixed
			// variant.
			name:       "mismatch_bare_vs_prefixed",
			positional: "foo",
			flagVal:    "bp:bar",
			wantErr:    "blueprint specified twice: 'bp:foo' (positional) and 'bp:bar' (--blueprint). Pass one or the other",
		},

		// Neither given.
		{
			name:    "neither",
			wantErr: "tailscale join requires a blueprint. Pass it as --blueprint=<id> or as the first positional argument",
		},

		// Empty after stripping the "bp:" prefix -- reuse the existing
		// blueprintIDFromFlag message so v1 tests stay valid.
		{
			name:    "flag_bp_only",
			flagVal: "bp:",
			wantErr: `--blueprint value "bp:" is empty after stripping the "bp:" prefix`,
		},
		{
			name:       "positional_bp_only",
			positional: "bp:",
			wantErr:    `--blueprint value "bp:" is empty after stripping the "bp:" prefix`,
		},

		// Validation errors propagate from blueprintIDFromFlag.
		{
			name:       "positional_invalid_char",
			positional: "bp:foo_bar",
			wantErr:    "must contain only letters, digits, and dashes",
		},
		{
			name:    "flag_leading_digit",
			flagVal: "1foo",
			wantErr: "must start with a letter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := resolveBlueprintArg(tt.positional, tt.flagVal)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if id != tt.wantID {
					t.Errorf("id = %q; want %q", id, tt.wantID)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got id=%q nil", tt.wantErr, id)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q; want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestResolveBlueprintArgFourFormsEquivalent asserts that the four
// invocations called out in the spec all normalize to the same id.
func TestResolveBlueprintArgFourFormsEquivalent(t *testing.T) {
	cases := []struct {
		name       string
		positional string
		flagVal    string
	}{
		{"flag_prefixed", "", "bp:foo"},
		{"flag_bare", "", "foo"},
		{"positional_prefixed", "bp:foo", ""},
		{"positional_bare", "foo", ""},
	}
	const want = "foo"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveBlueprintArg(c.positional, c.flagVal)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("id = %q; want %q", got, want)
			}
		})
	}
}

func TestNormalizeBlueprintArg(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"foo", "bp:foo"},
		{"bp:foo", "bp:foo"},
		{"bp:", "bp:"},
	}
	for _, tt := range tests {
		if got := normalizeBlueprintArg(tt.in); got != tt.want {
			t.Errorf("normalizeBlueprintArg(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestBlueprintIDFromFlag(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantID  string
		wantErr string
	}{
		{"empty", "", "", "--blueprint is required"},
		{"bp_prefix_only", "bp:", "", "is empty after stripping"},
		{"bare_id", "github-connector", "github-connector", ""},
		{"prefixed_id", "bp:github-connector", "github-connector", ""},
		{"alnum_id", "us-east-1", "us-east-1", ""},
		{"prefixed_alnum", "bp:us-east-1", "us-east-1", ""},
		{"uppercase_id", "GithubConnector", "GithubConnector", ""},
		{"leading_digit", "1foo", "", "must start with a letter"},
		{"prefixed_leading_digit", "bp:1foo", "", "must start with a letter"},
		{"slash", "bp:foo/bar", "", "must contain only letters, digits, and dashes"},
		{"at_sign", "bp:foo@bar", "", "must contain only letters, digits, and dashes"},
		{"space", "bp:foo bar", "", "must contain only letters, digits, and dashes"},
		{"underscore", "bp:foo_bar", "", "must contain only letters, digits, and dashes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := blueprintIDFromFlag(tt.in)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if id != tt.wantID {
					t.Errorf("id = %q; want %q", id, tt.wantID)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got id=%q nil", tt.wantErr, id)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q; want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
