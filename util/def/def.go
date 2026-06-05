// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package def implements conversions from string representations of data types
// that will fall back to default values.
package def

import (
	"strconv"
	"time"
)

// Bool returns the boolean value represented by the string,
// as parsed by [strconv.ParseBool].
// However, an empty or unparsable string will return the default value.
func Bool(s string, def bool) bool {
	return value(s, def, strconv.ParseBool)
}

// Duration returns the [time.Duration] value represented by the string,
// as parsed by [time.ParseDuration].
// However, an empty or unparsable string will return the default value.
func Duration(s string, def time.Duration) time.Duration {
	return value(s, def, time.ParseDuration)
}

func value[T any](s string, def T, conv func(string) (T, error)) T {
	if s == "" {
		return def
	}
	v, err := conv(s)
	if err != nil {
		return def
	}
	return v
}
