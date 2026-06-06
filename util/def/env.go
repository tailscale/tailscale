// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def

import (
	"cmp"
	"os"
)

// Getenv returns the value represented by the environment variable named by key.
// If the environment variable is unset or empty, it will return the default value.
func Getenv(key, def string) string {
	return cmp.Or(os.Getenv(key), def)
}

// GetenvBool returns the boolean value represented by the environment variable named by key,
// as parsed by [strconv.ParseBool].
// If the environment variable is unset or empty, it will return the default value.
func GetenvBool(key string, def bool) bool {
	return Bool(os.Getenv(key), def)
}

// GetenvFirst returns the first value that is set and not empty in the environment
// by looking up the environment variables that are named by keys.
// If none of the environment variables are valid, it will return the default value.
func GetenvFirst(keys []string, def string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return def
}
