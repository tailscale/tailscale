// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package bools contains the bools.Compare function.
package bools

// Compare compares two boolean values as if false is ordered before true.
func Compare[T ~bool](x, y T) int {
	switch {
	case x == false && y == true:
		return -1
	case x == true && y == false:
		return +1
	default:
		return 0
	}
}
