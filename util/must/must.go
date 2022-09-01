// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
