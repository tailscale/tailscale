// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package def parses strings and environment variables with fallback default
// values.
package def

import (
	"os"
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

// Env returns the value of environment variable name, or def when name is
// unset. A variable set to the empty string returns "" (not def).
func Env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// Envs returns the value of the first set environment variable in names, or def
// when none of them are set.
func Envs(names []string, def string) string {
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
	}
	return def
}

// EnvBool parses environment variable name as a bool, returning def when it is
// unset, empty, or invalid.
func EnvBool(name string, def bool) bool {
	return Bool(os.Getenv(name), def)
}

// EnvStringPointer returns a pointer to the value of environment variable name,
// or nil when name is unset. It distinguishes a variable set to the empty
// string (returns a pointer to "") from one that is unset (returns nil).
func EnvStringPointer(name string) *string {
	if v, ok := os.LookupEnv(name); ok {
		return &v
	}
	return nil
}

// EnvBoolPointer returns a pointer to the parsed bool value of environment
// variable name, or nil when name is unset or not a valid bool.
func EnvBoolPointer(name string) *bool {
	v, err := strconv.ParseBool(os.Getenv(name))
	if err != nil {
		return nil
	}
	return &v
}
