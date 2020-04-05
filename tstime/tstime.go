// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"strings"
	"sync"
	"time"
)

// zoneOf returns the RFC3339 zone suffix, or the empty string
// if it's invalid or not something we want to cache.
func zoneOf(s string) string {
	if strings.HasSuffix(s, "Z") {
		return ""
	}
	if len(s) < len("2020-04-05T15:56:00+08:00") {
		// Too short, invalid? Let time.Parse fail on it.
		return ""
	}
	zone := s[len(s)-len("+08:00"):]
	if c := zone[0]; c == '+' || c == '-' {
		min := zone[len("+08:"):]
		switch min {
		case "00", "15", "30":
			return zone
		}
	}
	return ""
}

// locCache maps from zone offset suffix string ("+08:00") =>
// *time.Location (from FixedLocation).
var locCache sync.Map

// Parse3339 is a wrapper around time.Parse(time.RFC3339Nano, s) that caches
// timezone Locations for future parses.
func Parse3339(s string) (time.Time, error) {
	zone := zoneOf(s)
	if zone == "" {
		return time.Parse(time.RFC3339Nano, s)
	}
	loci, ok := locCache.Load(zone)
	if ok {
		// TODO(bradfitz): just rewrite this do the trivial parsing by hand
		// which will be faster than Go's format-driven one. RFC3339 is trivial.
		return time.ParseInLocation(time.RFC3339Nano, s, loci.(*time.Location))
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	locCache.LoadOrStore(zone, t.Location())
	return t, nil
}
