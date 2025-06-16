// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package must assists in calling functions that must succeed.
//
// Example usage:
//
//	var target = must.Get(url.Parse(...))
//	must.Do(close())
package must

// Do panics if err is non-nil.
func Do(err error) {
	if err != nil {
		panic(err)
	}
}

// Get returns v as is. It panics if err is non-nil.
func Get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Get2 returns v1 and v2 as is. It panics if err is non-nil.
func Get2[T any, U any](v1 T, v2 U, err error) (T, U) {
	if err != nil {
		panic(err)
	}
	return v1, v2
}
