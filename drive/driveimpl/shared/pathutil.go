// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package shared

import (
	"net/url"
	"path"
	"strings"
)

// This file provides utility functions for working with URL paths. These are
// similar to functions in package path in the standard library, but differ in
// ways that are documented on the relevant functions.

const (
	sepString       = "/"
	sepStringAndDot = "/."
	sep             = '/'
)

// CleanAndSplit cleans the provided path p and splits it into its constituent
// parts. This is different from path.Split which just splits a path into prefix
// and suffix.
//
// If p is empty or contains only path separators, CleanAndSplit returns a slice
// of length 1 whose only element is "".
func CleanAndSplit(p string) []string {
	return strings.Split(strings.Trim(path.Clean(p), sepStringAndDot), sepString)
}

// Normalize normalizes the given path (e.g. dropping trailing slashes).
func Normalize(p string) string {
	return Join(CleanAndSplit(p)...)
}

// Parent extracts the parent of the given path.
func Parent(p string) string {
	parts := CleanAndSplit(p)
	return Join(parts[:len(parts)-1]...)
}

// Join behaves like path.Join() but also includes a leading slash.
//
// When parts are missing, the result is "/".
func Join(parts ...string) string {
	fullParts := make([]string, 0, len(parts))
	fullParts = append(fullParts, sepString)
	for _, part := range parts {
		fullParts = append(fullParts, part)
	}
	return path.Join(fullParts...)
}

// JoinEscaped is like Join but path escapes each part.
func JoinEscaped(parts ...string) string {
	fullParts := make([]string, 0, len(parts))
	fullParts = append(fullParts, sepString)
	for _, part := range parts {
		fullParts = append(fullParts, url.PathEscape(part))
	}
	return path.Join(fullParts...)
}

// IsRoot determines whether a given path p is the root path, defined as either
// empty or "/".
func IsRoot(p string) bool {
	return p == "" || p == sepString
}

// Base is like path.Base except that it returns "" for the root folder
func Base(p string) string {
	if IsRoot(p) {
		return ""
	}
	return path.Base(p)
}
