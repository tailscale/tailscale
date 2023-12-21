// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package pathutil provides utility functions for working with URL paths.
package pathutil

import (
	"path"
	"strings"
)

const (
	sepString       = "/"
	sepStringAndDot = "/."
	sep             = '/'
)

func Split(p string) []string {
	return strings.Split(strings.Trim(path.Clean(p), sepStringAndDot), sepString)
}

func Join(parts ...string) string {
	return sepString + strings.Join(parts, sepString)
}

func IsRoot(path string) bool {
	return len(path) == 0 || len(path) == 1 && path[0] == sep
}
