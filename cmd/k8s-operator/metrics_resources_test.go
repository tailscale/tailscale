// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"strings"
	"testing"
)

func TestTruncateLabelValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // empty means expect input unchanged
	}{
		{
			name:  "short value unchanged",
			input: "my-service",
		},
		{
			name:  "exactly 63 chars unchanged",
			input: strings.Repeat("a", 63),
		},
		{
			name:  "64 chars gets truncated",
			input: strings.Repeat("a", 64),
		},
		{
			name:  "very long value gets truncated",
			input: "tailscale-nginx-clickhouse-o11y-server-https-with-extra-long-suffix-that-exceeds-limit",
		},
		{
			name:  "253 chars (max k8s resource name)",
			input: strings.Repeat("x", 253),
		},
		{
			name:  "empty string unchanged",
			input: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateLabelValue(tt.input)
			if len(got) > 63 {
				t.Errorf("truncateLabelValue(%q) = %q (len %d), exceeds 63 chars", tt.input, got, len(got))
			}
			if len(tt.input) <= 63 && got != tt.input {
				t.Errorf("truncateLabelValue(%q) = %q, want unchanged input", tt.input, got)
			}
			if len(tt.input) > 63 && got == tt.input {
				t.Errorf("truncateLabelValue(%q) was not truncated", tt.input)
			}
		})
	}
}

func TestTruncateLabelValueDeterministic(t *testing.T) {
	input := strings.Repeat("a", 100)
	first := truncateLabelValue(input)
	for i := 0; i < 10; i++ {
		got := truncateLabelValue(input)
		if got != first {
			t.Fatalf("non-deterministic: got %q, want %q", got, first)
		}
	}
}

func TestTruncateLabelValueUniqueness(t *testing.T) {
	// Two inputs sharing a long prefix but differing at the end should produce different outputs.
	a := strings.Repeat("a", 100) + "-one"
	b := strings.Repeat("a", 100) + "-two"
	if truncateLabelValue(a) == truncateLabelValue(b) {
		t.Errorf("collision: %q and %q produce the same truncated label", a, b)
	}
}
