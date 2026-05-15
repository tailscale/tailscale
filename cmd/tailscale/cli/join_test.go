// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"
)

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
