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

// Compare returns an integer comparing two strings as version
// numbers. The result will be 0 if v1==v2, -1 if v1 < v2, and +1 if
// v1 > v2.
func Compare(v1, v2 string) int {
	// Get empty strings out of the way.
	if len(v1) == 0 {
		if len(v2) == 0 {
			return 0
		}
		return -1
	}
	if len(v2) == 0 {
		return +1
	}

	i, j := 0, 0
	for {
		// Consume runs of non-numeral alpha.
		for {
			a, b := v1[i], v2[j]
			if isnum(a) {
				if isnum(b) {
					// We're switching to numbers.
					break
				}
				// v1 has the shorter alpha string ending at i, so it's less.
				return -1
			}
			if isnum(b) {
				// v1 is the longer alpha string ending at i, so it's greater.
				return +1
			}

			// Compare the next char in our text string.
			if a < b {
				return -1
			}
			if a > b {
				return +1
			}

			// Check the next char.
			i++
			j++
			if i == len(v1) || j == len(v2) {
				goto exhausted
			}
		}

		// Discard runs of zero. i and j can diverge here without meaning
		// there's any difference between v1 and v2.
		for i < len(v1) && v1[i] == '0' {
			i++
		}
		for j < len(v2) && v2[j] == '0' {
			j++
		}
		if i == len(v1) || j == len(v2) {
			goto exhausted
		}

		// Compare runs of numerals.
		for {
			// Discard runs of common numerals.
			a, b := v1[i], v2[j]
			if !isnum(a) {
				if !isnum(b) {
					// The numbers were equal. We're switching to alpha.
					break
				}
				// v2 has more digits, so v1 is less.
				return -1
			}
			if !isnum(b) {
				// v1 has more digits, so v1 is greater.
				return +1
			}
			if a == b {
				// Check the next numeral.
				i++
				j++
				if i == len(v1) || j == len(v2) {
					goto exhausted
				}
				continue
			}

			// Since we've found numeral a != numeral b, then the shortest
			// remaining run of numerals points to the lower version. If they're
			// equal length then smallest is determined directly from a and b.
			for {
				// Check if v1[i+1] continues to be a number.
				var cm bool
				if i+1 < len(v1) && isnum(v1[i+1]) {
					cm = true
					i++
				}

				// Check if v2[j+1] continues to be a number.
				var cn bool
				if j+1 < len(v2) && isnum(v2[j+1]) {
					cn = true
					j++
				}

				if !cm {
					if !cn {
						// Both numbers are the same length, compare a and b.
						if a < b {
							return -1
						}
						return +1
					}
					// v1 has the shorter run of numerals, so v1 is less.
					return -1
				}
				if !cn {
					// v2 has the shorter run of numerals, so v1 is greater.
					return +1
				}
			}
		}
	}
exhausted:
	if i < len(v1) {
		// We still had characters in v1, so v1 must have been longer/greater.
		return +1
	}
	if j < len(v2) {
		// We still had characters in v2, so v1 must have been shorter/less.
		return -1
	}
	// We exhausted v1 and v2 at the same time. They're equal.
	return 0
}

func isnum(c byte) bool {
	// The previous version of this coded relied on strconv.ParseUint which only
	// supports ASCII numerals, and so we shall too.
	return c >= '0' && c <= '9'
}
