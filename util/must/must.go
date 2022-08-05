// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package must assists in calling functions that must succeed.
//
// Example usage:
//	var target = must.Do(url.Parse(...))
package must

// Do returns v as is. It panics if err is non-nil.
func Do[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
