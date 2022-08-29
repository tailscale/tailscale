// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package uniq provides removal of adjacent duplicate elements in slices.
// It is similar to the unix command uniq.
package uniq

// ModifySlice removes adjacent duplicate elements from the given slice. It
// adjusts the length of the slice appropriately and zeros the tail.
//
// ModifySlice does O(len(*slice)) operations.
func ModifySlice[E comparable](slice *[]E) {
	// Remove duplicates
	dst := 0
	for i := 1; i < len(*slice); i++ {
		if (*slice)[i] == (*slice)[dst] {
			continue
		}
		dst++
		(*slice)[dst] = (*slice)[i]
	}

	// Zero out the elements we removed at the end of the slice
	end := dst + 1
	var zero E
	for i := end; i < len(*slice); i++ {
		(*slice)[i] = zero
	}

	// Truncate the slice
	if end < len(*slice) {
		*slice = (*slice)[:end]
	}
}
