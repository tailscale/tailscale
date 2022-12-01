// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ptr contains the ptr.To function.
package ptr

// To returns a pointer to a shallow copy of v.
func To[T any](v T) *T {
	return &v
}
