// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package def

import (
	"os"
	"strconv"

	"tailscale.com/types/opt"
)

// Getenv returns the value represented by the environment variable named by key.
// If the environment variable is unset or empty, it will return the default value.
func Getenv(key, def string) string {
	return value(os.Getenv(key), def, noop)
}

// GetenvBool returns the boolean value represented by the environment variable named by key,
// as parsed by [strconv.ParseBool].
// If the environment variable is unset or empty, it will return the default value.
func GetenvBool(key string, def bool) bool {
	return value(os.Getenv(key), def, strconv.ParseBool)
}

// GetenvOptBool returns the optional boolean value
// represented by the environment variable named by key,
// as parsed by [opt.Bool].
// If the environment variable is unset or empty, it will return the default value.
func GetenvOptBool(key string, def bool) bool {
	vs := os.Getenv(key)
	if vs == "" {
		return def
	}
	v, _ := opt.Bool(vs).Get()
	return v
}

// GetenvResolve returns the first value that is set in the environment
// by looking up the environment variables named by keys.
// If all of the environment variables are unset, it will return the default value.
func GetenvResolve(keys []string, def string) string {
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			return v
		}
	}
	return def
}

// LookupEnv returns the value represented by the environment variable named by key.
// If the environment variable is unset, it will return the default value.
func LookupEnv(name, defVal string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return defVal
}
