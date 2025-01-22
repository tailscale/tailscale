// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package feature tracks which features are linked into the binary.
package feature

var in = map[string]bool{}

// Register notes that the named feature is linked into the binary.
func Register(name string) {
	if _, ok := in[name]; ok {
		panic("duplicate feature registration for " + name)
	}
	in[name] = true
}
