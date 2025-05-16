// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// ValidMeshKey is a regular expression that matches a valid mesh key,
	// which must be a 64-character hexadecimal string (lowercase only).
	ValidMeshKey = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CheckMeshKey checks if the provided key is a valid mesh key.
// It trims any leading or trailing whitespace and returns an error if the key
// does not match the expected format. If the key is empty or valid, it returns
// the trimmed key and a nil error. The key must be a 64-character
// hexadecimal string (lowercase only).
func CheckMeshKey(key string) (string, error) {
	if key == "" {
		return key, nil
	}

	key = strings.TrimSpace(key)
	if !ValidMeshKey.MatchString(key) {
		return "", fmt.Errorf("key must contain exactly 64 hex digits")
	}
	return key, nil
}
