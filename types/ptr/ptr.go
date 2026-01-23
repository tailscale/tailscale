// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ptr contains the ptr.To function.
package ptr

// To returns a pointer to a shallow copy of v.
func To[T any](v T) *T {
	return &v
}
