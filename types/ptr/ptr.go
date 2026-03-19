// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ptr contains the ptr.To function.
//
// Deprecated: Use Go 1.26's new(value) expression instead.
// See https://go.dev/doc/go1.26#language.
package ptr

// To returns a pointer to a shallow copy of v.
//
// Deprecated: Use Go 1.26's new(value) expression instead.
// For example, ptr.To(42) can be written as new(42).
// See https://go.dev/doc/go1.26#language.
//
//go:fix inline
func To[T any](v T) *T {
	return new(v)
}
