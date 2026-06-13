// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package def parses strings with fallback default values.
package def

import (
	"strconv"
	"time"
)

// Bool parses s as a bool, returning def when s is empty or invalid.
func Bool(s string, def bool) bool {
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}

// Duration parses s as a time.Duration, returning def when s is empty or invalid.
func Duration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return v
}
