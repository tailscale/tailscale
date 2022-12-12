// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
)

var memZ = mem.S("Z")

// zoneOf returns the RFC3339 zone suffix (either "Z" or like
// "+08:30"), or the empty string if it's invalid or not something we
// want to cache.
func zoneOf(s mem.RO) mem.RO {
	if mem.HasSuffix(s, memZ) {
		return memZ
	}
	if s.Len() < len("2020-04-05T15:56:00+08:00") {
		// Too short, invalid? Let time.Parse fail on it.
		return mem.S("")
	}
	zone := s.SliceFrom(s.Len() - len("+08:00"))
	if c := zone.At(0); c == '+' || c == '-' {
		min := zone.SliceFrom(len("+08:"))
		if min.EqualString("00") || min.EqualString("15") || min.EqualString("30") {
			return zone
		}
	}
	return mem.S("")
}

// locCache maps from hash of zone offset suffix string ("+08:00") =>
// {zone string, *time.Location (from FixedLocation)}.
var locCache sync.Map

type locCacheEntry struct {
	zone string
	loc  *time.Location
}

func getLocation(zone, timeValue mem.RO) (*time.Location, error) {
	if zone.EqualString("Z") {
		return time.UTC, nil
	}
	key := zone.MapHash()
	if entry, ok := locCache.Load(key); ok {
		// We're keying only on a hash; double-check zone to ensure no spurious collisions.
		e := entry.(locCacheEntry)
		if zone.EqualString(e.zone) {
			return e.loc, nil
		}
	}
	// TODO(bradfitz): just parse it and call time.FixedLocation.
	// For now, just have time.Parse do it once:
	t, err := time.Parse(time.RFC3339Nano, timeValue.StringCopy())
	if err != nil {
		return nil, err
	}
	loc := t.Location()
	locCache.LoadOrStore(key, locCacheEntry{zone: zone.StringCopy(), loc: loc})
	return loc, nil
}

func parse3339m(s mem.RO) (time.Time, error) {
	zone := zoneOf(s)
	if zone.Len() == 0 {
		// Invalid or weird timezone offset. Use slow path,
		// which'll probably return an error.
		return time.Parse(time.RFC3339Nano, s.StringCopy())
	}
	loc, err := getLocation(zone, s)
	if err != nil {
		return time.Time{}, err
	}
	s = s.SliceTo(s.Len() - zone.Len()) // remove zone suffix
	var year, mon, day, hr, min, sec, nsec int
	const baseLen = len("2020-04-05T15:56:00")
	if s.Len() < baseLen ||
		!parseInt(s.SliceTo(4), &year) ||
		s.At(4) != '-' ||
		!parseInt(s.Slice(5, 7), &mon) ||
		s.At(7) != '-' ||
		!parseInt(s.Slice(8, 10), &day) ||
		s.At(10) != 'T' ||
		!parseInt(s.Slice(11, 13), &hr) ||
		s.At(13) != ':' ||
		!parseInt(s.Slice(14, 16), &min) ||
		s.At(16) != ':' ||
		!parseInt(s.Slice(17, 19), &sec) {
		return time.Time{}, errors.New("invalid time")
	}
	nsStr := s.SliceFrom(baseLen)
	if nsStr.Len() != 0 {
		if nsStr.At(0) != '.' {
			return time.Time{}, errors.New("invalid optional nanosecond prefix")
		}
		nsStr = nsStr.SliceFrom(1)
		if !parseInt(nsStr, &nsec) {
			return time.Time{}, fmt.Errorf("invalid optional nanosecond number %q", nsStr.StringCopy())
		}
		for i := 0; i < len("999999999")-nsStr.Len(); i++ {
			nsec *= 10
		}
	}
	return time.Date(year, time.Month(mon), day, hr, min, sec, nsec, loc), nil
}

func parseInt(s mem.RO, dst *int) bool {
	if s.Len() == 0 || s.Len() > len("999999999") {
		*dst = 0
		return false
	}
	n := 0
	for i := 0; i < s.Len(); i++ {
		d := s.At(i) - '0'
		if d > 9 {
			*dst = 0
			return false
		}
		n = n*10 + int(d)
	}
	*dst = n
	return true
}

// Parse3339 is a wrapper around time.Parse(time.RFC3339Nano, s) that caches
// timezone Locations for future parses.
func Parse3339(s string) (time.Time, error) {
	return parse3339m(mem.S(s))
}

// Parse3339B is Parse3339 but for byte slices.
func Parse3339B(b []byte) (time.Time, error) {
	return parse3339m(mem.B(b))
}

// ParseDuration is more expressive than time.ParseDuration,
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
