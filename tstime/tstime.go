// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Parse3339 is a wrapper around time.Parse(time.RFC3339, s).
func Parse3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// Parse3339B is Parse3339 but for byte slices.
func Parse3339B(b []byte) (time.Time, error) {
	var t time.Time
	if err := t.UnmarshalText(b); err != nil {
		return Parse3339(string(b)) // reproduce same error message
	}
	return t, nil
}

// ParseDuration is more expressive than [time.ParseDuration],
// also accepting 'd' (days) and 'w' (weeks) literals.
func ParseDuration(s string) (time.Duration, error) {
	for {
		end := strings.IndexAny(s, "dw")
		if end < 0 {
			break
		}
		start := end - (len(s[:end]) - len(strings.TrimRight(s[:end], "0123456789")))
		n, err := strconv.Atoi(s[start:end])
		if err != nil {
			return 0, err
		}
		hours := 24
		if s[end] == 'w' {
			hours *= 7
		}
		s = s[:start] + s[end+1:] + strconv.Itoa(n*hours) + "h"
	}
	return time.ParseDuration(s)
}

// Sleep is like [time.Sleep] but returns early upon context cancelation.
// It reports whether the full sleep duration was achieved.
func Sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
