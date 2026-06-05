// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def_test

import (
	"strconv"
	"testing"
	"time"

	"tailscale.com/util/def"
)

func FuzzBool(f *testing.F) {
	// defBool was copy-pasted multiple times, before being replaced:
	defBool := func(a string, def bool) bool {
		if a == "" {
			return def
		}
		v, err := strconv.ParseBool(a)
		if err != nil {
			return def
		}
		return v
	}

	for _, tc := range []string{
		"",
		"invalid",

		// strconv.ParseBool accepts:
		"1", "t", "T", "TRUE", "true", "True",
		"0", "f", "F", "FALSE", "false", "False",
	} {
		f.Add(tc, true)
		f.Add(tc, false)
	}
	f.Fuzz(func(t *testing.T, s string, d bool) {
		want := defBool(s, d)
		got := def.Bool(s, d)
		if got != want {
			t.Errorf("def.Bool(%q, %t): got %t, want %t", s, d, got, want)
		}
	})
}

func FuzzDuration(f *testing.F) {
	// defDuration was copy-pasted multiple times, before being replaced:
	defDuration := func(a string, def time.Duration) time.Duration {
		if a == "" {
			return def
		}
		v, err := time.ParseDuration(a)
		if err != nil {
			return def
		}
		return v
	}

	for _, tc := range []string{
		"",
		"invalid",

		// A duration string is a possibly signed sequence of
		// decimal numbers, each with optional fraction and a unit suffix,
		// such as "300ms", "-1.5h" or "2h45m".
		// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
		"300ms", "-1.5h", "2h45m",
	} {
		f.Add(tc, int64(0))
		f.Add(tc, int64(-1))
		f.Add(tc, int64(1))
	}
	f.Fuzz(func(t *testing.T, s string, d int64) {
		dur := time.Duration(d)
		want := defDuration(s, dur)
		got := def.Duration(s, dur)
		if got != want {
			t.Errorf("def.Duration(%q, %s): got %s, want %s", s, dur, got, want)
		}
	})
}
