// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"reflect"
	"testing"
)

func TestSplitRedirectURIs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single URI",
			input:    "https://example.com/callback",
			expected: []string{"https://example.com/callback"},
		},
		{
			name:     "multiple URIs",
			input:    "https://example.com/callback\nhttps://example.com/oauth\nhttps://example.com/auth",
			expected: []string{"https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"},
		},
		{
			name:     "URIs with extra whitespace",
			input:    "  https://example.com/callback  \n\n  https://example.com/oauth  \n\n\n",
			expected: []string{"https://example.com/callback", "https://example.com/oauth"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name:     "only whitespace",
			input:    "   \n\n   \n   ",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitRedirectURIs(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("splitRedirectURIs(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestJoinRedirectURIs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "single URI",
			input:    []string{"https://example.com/callback"},
			expected: "https://example.com/callback",
		},
		{
			name:     "multiple URIs",
			input:    []string{"https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"},
			expected: "https://example.com/callback\nhttps://example.com/oauth\nhttps://example.com/auth",
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinRedirectURIs(tt.input)
			if got != tt.expected {
				t.Errorf("joinRedirectURIs(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
