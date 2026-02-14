// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
)

func TestParseMDX(t *testing.T) {
	input := `---
clientVersion: "1.94.1"
---
##### All Platforms
* New: Core fix (#123) @user
* Changed: Improved [performance](https://tailscale.com)
##### Linux
* Fixed: Systemd fix [kb-article]
* Something uncategorized
##### Windows
* Should be ignored
`
	r := strings.NewReader(input)
	data, err := parseMDX(r)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Verify Metadata
	if data.Version != "1.94.1" {
		t.Errorf("Expected version 1.94.1, got %q", data.Version)
	}

	// Verify Items are collected and cleaned
	expected := []string{
		"New: Core fix",
		"Changed: Improved performance",
		"Fixed: Systemd fix",
		"Something uncategorized",
	}

	if len(data.Items) != len(expected) {
		t.Fatalf("Expected %d items, got %d", len(expected), len(data.Items))
	}

	for i, v := range data.Items {
		if v != expected[i] {
			t.Errorf("At index %d: expected %q, got %q", i, expected[i], v)
		}
	}
}

func TestCleanLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"strip PR", "Fix bug (#123)", "Fix bug"},
		{"strip user", "Fix by @user", "Fix by"},
		{"strip markdown link", "See [docs](https://tailscale.com)", "See docs"},
		{"strip brackets", "[TKA] is [stable]", "TKA is stable"},
		{"strip kb links", "Check [kb-article-name]", "Check"},
		{"strip backticks", "Use `tailscale up`", "Use tailscale up"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanLine(tt.input)
			if got != tt.expected {
				t.Errorf("cleanLine(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}
