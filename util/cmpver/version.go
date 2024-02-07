// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cmpver implements a variant of debian version number
// comparison.
//
// A version is a string consisting of alternating non-numeric and
// numeric fields. When comparing two versions, each one is broken
// down into its respective fields, and the fields are compared
// pairwise. The comparison is lexicographic for non-numeric fields,
// numeric for numeric fields. The first non-equal field pair
// determines the ordering of the two versions.
//
// This comparison scheme is a simplified version of Debian's version
// number comparisons. Debian differs in a few details of
// lexicographical field comparison, where certain characters have
// special meaning and ordering. We don't need that, because Tailscale
// version numbers don't need it.
package cmpver

import (
	"fmt"
	"strconv"
	"strings"
)

// Less reports whether v1 is less than v2.
//
// Note that "12" is less than "12.0".
func Less(v1, v2 string) bool {
	return Compare(v1, v2) < 0
}

// LessEq reports whether v1 is less than or equal to v2.
//
// Note that "12" is less than "12.0".
func LessEq(v1, v2 string) bool {
	return Compare(v1, v2) <= 0
}

func isnum(r rune) bool {
	return r >= '0' && r <= '9'
}

func notnum(r rune) bool {
	return !isnum(r)
}

// Compare returns an integer comparing two strings as version numbers.
// The result will be -1, 0, or 1 representing the sign of v1 - v2:
//
//	Compare(v1, v2)  < 0  if v1  < v2
//	                == 0  if v1 == v2
//	                 > 0  if v1  > v2
func Compare(v1, v2 string) int {
	var (
		f1, f2 string
		n1, n2 uint64
		err    error
	)
	for v1 != "" || v2 != "" {
		// Compare the non-numeric character run lexicographically.
		f1, v1 = splitPrefixFunc(v1, notnum)
		f2, v2 = splitPrefixFunc(v2, notnum)

		if res := strings.Compare(f1, f2); res != 0 {
			return res
		}

		// Compare the numeric character run numerically.
		f1, v1 = splitPrefixFunc(v1, isnum)
		f2, v2 = splitPrefixFunc(v2, isnum)

		// ParseUint refuses to parse empty strings, which would only
		// happen if we reached end-of-string. We follow the Debian
		// convention that empty strings mean zero, because
		// empirically that produces reasonable-feeling comparison
		// behavior.
		n1 = 0
		if f1 != "" {
			n1, err = strconv.ParseUint(f1, 10, 64)
			if err != nil {
				panic(fmt.Sprintf("all-number string %q didn't parse as string: %s", f1, err))
			}
		}

		n2 = 0
		if f2 != "" {
			n2, err = strconv.ParseUint(f2, 10, 64)
			if err != nil {
				panic(fmt.Sprintf("all-number string %q didn't parse as string: %s", f2, err))
			}
		}

		switch {
		case n1 == n2:
		case n1 < n2:
			return -1
		case n1 > n2:
			return 1
		}
	}

	// Only way to reach here is if v1 and v2 run out of fields
	// simultaneously - i.e. exactly equal versions.
	return 0
}

// splitPrefixFunc splits s at the first rune where f(rune) is false.
func splitPrefixFunc(s string, f func(rune) bool) (string, string) {
	for i, r := range s {
		if !f(r) {
			return s[:i], s[i:]
		}
	}
	return s, s[:0]
}
