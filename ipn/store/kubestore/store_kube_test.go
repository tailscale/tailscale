// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubestore

import (
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestStore_String(t *testing.T) {
	s := &Store{
		secretName: "test-secret",
	}

	if got := s.String(); got != "kube.Store" {
		t.Errorf("String() = %q, want %q", got, "kube.Store")
	}
}

func TestSanitizeKey(t *testing.T) {
	tests := []struct {
		name  string
		input ipn.StateKey
		want  string
	}{
		{
			name:  "alphanumeric",
			input: "abc123",
			want:  "abc123",
		},
		{
			name:  "with_dashes",
			input: "test-key-name",
			want:  "test-key-name",
		},
		{
			name:  "with_underscores",
			input: "test_key_name",
			want:  "test_key_name",
		},
		{
			name:  "with_dots",
			input: "test.key.name",
			want:  "test.key.name",
		},
		{
			name:  "with_invalid_chars",
			input: "test/key:name",
			want:  "test_key_name",
		},
		{
			name:  "with_spaces",
			input: "test key name",
			want:  "test_key_name",
		},
		{
			name:  "with_special_chars",
			input: "test@key#name",
			want:  "test_key_name",
		},
		{
			name:  "mixed_case",
			input: "TestKeyName",
			want:  "TestKeyName",
		},
		{
			name:  "all_invalid",
			input: "@#$%^&*()",
			want:  "_________",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:  "path_like",
			input: "/var/lib/tailscale/state",
			want:  "_var_lib_tailscale_state",
		},
		{
			name:  "url_like",
			input: "https://example.com/path?query=value",
			want:  "https___example.com_path_query_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeKey(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeKey(%q) = %q, want %q", tt.input, got, tt.want)
			}

			// Verify result contains only valid characters
			for _, r := range got {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
					t.Errorf("sanitizeKey(%q) = %q contains invalid char %c", tt.input, got, r)
				}
			}
		})
	}
}

func TestSanitizeKey_Idempotent(t *testing.T) {
	// Sanitizing a key twice should produce the same result
	tests := []ipn.StateKey{
		"valid-key",
		"invalid/key",
		"test@key#name",
		"path/to/state",
	}

	for _, key := range tests {
		first := sanitizeKey(key)
		second := sanitizeKey(ipn.StateKey(first))

		if first != second {
			t.Errorf("sanitizeKey not idempotent for %q: first=%q, second=%q", key, first, second)
		}
	}
}

func TestSanitizeKey_PreservesValidChars(t *testing.T) {
	// All valid characters should pass through unchanged
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
	result := sanitizeKey(ipn.StateKey(validChars))

	if result != validChars {
		t.Errorf("sanitizeKey(%q) = %q, want %q", validChars, result, validChars)
	}
}

func TestSanitizeKey_Length(t *testing.T) {
	// Length should be preserved
	tests := []ipn.StateKey{
		"short",
		"a-very-long-key-name-that-has-many-characters-in-it",
		"x",
		"",
	}

	for _, key := range tests {
		result := sanitizeKey(key)
		if len(result) != len(string(key)) {
			t.Errorf("sanitizeKey(%q) length = %d, want %d", key, len(result), len(string(key)))
		}
	}
}

func TestStore_SetDialer(t *testing.T) {
	// This test verifies SetDialer doesn't panic
	// Full testing would require mocking kubeclient.Client
	s := &Store{
		secretName: "test-secret",
	}

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetDialer panicked: %v", r)
		}
	}()

	s.SetDialer(nil)
}

func TestSanitizeKey_Unicode(t *testing.T) {
	// Unicode characters should be replaced with underscore
	tests := []struct {
		input string
		desc  string
	}{
		{input: "hello世界", desc: "Chinese characters"},
		{input: "тест", desc: "Cyrillic characters"},
		{input: "café", desc: "Accented characters"},
		{input: "🔑key", desc: "Emoji"},
		{input: "αβγ", desc: "Greek letters"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := sanitizeKey(ipn.StateKey(tt.input))

			// Should only contain valid chars
			for _, r := range result {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
					t.Errorf("sanitizeKey(%q) = %q contains invalid char %c", tt.input, result, r)
				}
			}

			// Should contain at least some underscores (since we replaced unicode)
			if !strings.Contains(result, "_") && len(tt.input) > 0 {
				t.Errorf("sanitizeKey(%q) = %q, expected underscores for unicode replacement", tt.input, result)
			}
		})
	}
}

func TestSanitizeKey_KubernetesRestrictions(t *testing.T) {
	// Test that sanitized keys would be valid Kubernetes secret keys
	tests := []ipn.StateKey{
		"simple",
		"with-dash",
		"with_underscore",
		"with.dot",
		"MixedCase123",
		"has/slash",
		"has:colon",
		"has spaces",
		"has@symbols#here",
	}

	for _, key := range tests {
		result := sanitizeKey(key)

		// Kubernetes secret keys must:
		// - consist of alphanumeric characters, '-', '_' or '.'
		// This is what our sanitizeKey function ensures
		for _, r := range result {
			valid := (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '-' || r == '_' || r == '.'

			if !valid {
				t.Errorf("sanitizeKey(%q) = %q contains Kubernetes-invalid char %c", key, result, r)
			}
		}
	}
}

// Benchmark sanitizeKey performance
func BenchmarkSanitizeKey(b *testing.B) {
	keys := []ipn.StateKey{
		"simple-key",
		"path/to/state/file",
		"https://example.com/path?query=value",
		"key-with-many-invalid-@#$%-characters",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizeKey(keys[i%len(keys)])
	}
}

func BenchmarkSanitizeKey_ValidOnly(b *testing.B) {
	key := ipn.StateKey("valid-key-123.with_valid.chars")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizeKey(key)
	}
}

func BenchmarkSanitizeKey_AllInvalid(b *testing.B) {
	key := ipn.StateKey("@#$%^&*()/\\:;'\"<>?,")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizeKey(key)
	}
}
