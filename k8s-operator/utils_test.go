// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"strings"
	"testing"

	"tailscale.com/util/dnsname"
)

func TestTruncateWithHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // empty means expect input unchanged
	}{
		{
			name:  "short-value-unchanged",
			input: "my-service",
		},
		{
			name:  "exactly-63-chars-unchanged",
			input: strings.Repeat("a", 63),
		},
		{
			name:  "64-chars-gets-truncated",
			input: strings.Repeat("a", 64),
		},
		{
			name:  "very-long-value-gets-truncated",
			input: "tailscale-nginx-clickhouse-o11y-server-https-with-extra-long-suffix-that-exceeds-limit",
		},
		{
			name:  "253-chars-max-k8s-resource-name",
			input: strings.Repeat("x", 253),
		},
		{
			name:  "empty-string-unchanged",
			input: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateWithHash(tt.input)
			if len(got) > 63 {
				t.Errorf("TruncateWithHash(%q) = %q (len %d), exceeds 63 chars", tt.input, got, len(got))
			}
			if len(tt.input) <= 63 && got != tt.input {
				t.Errorf("TruncateWithHash(%q) = %q, want unchanged input", tt.input, got)
			}
			if len(tt.input) > 63 && got == tt.input {
				t.Errorf("TruncateWithHash(%q) was not truncated", tt.input)
			}
		})
	}
}

func TestTruncateWithHashDeterministic(t *testing.T) {
	input := strings.Repeat("a", 100)
	first := TruncateWithHash(input)
	for range 10 {
		got := TruncateWithHash(input)
		if got != first {
			t.Fatalf("non-deterministic: got %q, want %q", got, first)
		}
	}
}

func TestTruncateWithHashUniqueness(t *testing.T) {
	// Two inputs sharing a long prefix but differing at the end should produce different outputs.
	a := strings.Repeat("a", 100) + "-one"
	b := strings.Repeat("a", 100) + "-two"
	if TruncateWithHash(a) == TruncateWithHash(b) {
		t.Errorf("collision: %q and %q produce the same truncated label", a, b)
	}
}

func TestTruncateWithHashDNSLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "short-hostname-unchanged",
			input: "default-my-service",
			want:  "default-my-service",
		},
		{
			name:  "exactly-63-chars-unchanged",
			input: strings.Repeat("a", 63),
			want:  strings.Repeat("a", 63),
		},
		{
			name:  "long-hostname-truncated",
			input: "tailscale-external-services-harry1027133059-trefknee01-bee-oqggo-kinfe-0-g",
			want:  "tailscale-external-services-harry1027133059-trefknee01-0908ae76",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateWithHash(tt.input)
			if got != tt.want {
				t.Errorf("TruncateWithHash(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if err := dnsname.ValidLabel(got); err != nil {
				t.Errorf("TruncateWithHash(%q) = %q is not a valid DNS label: %v", tt.input, got, err)
			}
		})
	}
}
