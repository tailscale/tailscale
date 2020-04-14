// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstime defines Tailscale-specific time utilities.
package tstime

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// zoneOf returns the RFC3339 zone suffix (either "Z" or like
// "+08:30"), or the empty string if it's invalid or not something we
// want to cache.
func zoneOf(s string) string {
	if strings.HasSuffix(s, "Z") {
		return "Z"
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

func getLocation(zone, timeValue string) (*time.Location, error) {
	if zone == "Z" {
		return time.UTC, nil
	}
	if loci, ok := locCache.Load(zone); ok {
		return loci.(*time.Location), nil
	}
	// TODO(bradfitz): just parse it and call time.FixedLocation.
	// For now, just have time.Parse do it once:
	t, err := time.Parse(time.RFC3339Nano, timeValue)
	if err != nil {
		return nil, err
	}
	loc := t.Location()
	locCache.LoadOrStore(zone, loc)
	return loc, nil

}

// Parse3339 is a wrapper around time.Parse(time.RFC3339Nano, s) that caches
// timezone Locations for future parses.
func Parse3339(s string) (time.Time, error) {
	zone := zoneOf(s)
	if zone == "" {
		// Invalid or weird timezone offset. Use slow path,
		// which'll probably return an error.
		return time.Parse(time.RFC3339Nano, s)
	}
	loc, err := getLocation(zone, s)
	if err != nil {
		return time.Time{}, err
	}
	s = s[:len(s)-len(zone)] // remove zone suffix
	var year, mon, day, hr, min, sec, nsec int
	const baseLen = len("2020-04-05T15:56:00")
	if len(s) < baseLen ||
		!parseInt(s[:4], &year) ||
		s[4] != '-' ||
		!parseInt(s[5:7], &mon) ||
		s[7] != '-' ||
		!parseInt(s[8:10], &day) ||
		s[10] != 'T' ||
		!parseInt(s[11:13], &hr) ||
		s[13] != ':' ||
		!parseInt(s[14:16], &min) ||
		s[16] != ':' ||
		!parseInt(s[17:19], &sec) {
		return time.Time{}, errors.New("invalid time")
	}
	nsStr := s[baseLen:]
	if nsStr != "" {
		if nsStr[0] != '.' {
			return time.Time{}, errors.New("invalid optional nanosecond prefix")
		}
		if !parseInt(nsStr[1:], &nsec) {
			return time.Time{}, fmt.Errorf("invalid optional nanosecond number %q", nsStr[1:])
		}
		for i := 0; i < len("999999999")-(len(nsStr)-1); i++ {
			nsec *= 10
		}
	}
	return time.Date(year, time.Month(mon), day, hr, min, sec, nsec, loc), nil
}

func parseInt(s string, dst *int) bool {
	if len(s) == 0 || len(s) > len("999999999") {
		*dst = 0
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		d := s[i] - '0'
		if d > 9 {
			*dst = 0
			return false
		}
		n = n*10 + int(d)
	}
	*dst = n
	return true
}
