// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package def parses strings with fallback default values.
package def

import (
	"math"
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

// Int parses s as an int, returning def when s is empty or invalid.
func Int(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

// Float64 parses s as a float64, returning def when s is empty, invalid,
// or parses to a non-finite value (NaN or Inf).
func Float64(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return def
	}
	return v
}
