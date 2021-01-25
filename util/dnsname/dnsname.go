// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsname contains string functions for working with DNS names.
package dnsname

import "strings"

// HasSuffix reports whether the provided DNS name ends with the
// component(s) in suffix, ignoring any trailing dots.
//
// If suffix is the empty string, HasSuffix always reports false.
func HasSuffix(name, suffix string) bool {
	name = strings.TrimSuffix(name, ".")
	suffix = strings.TrimSuffix(suffix, ".")
	nameBase := strings.TrimSuffix(name, suffix)
	return len(nameBase) < len(name) && strings.HasSuffix(nameBase, ".")
}

// ToBaseName removes the domain ending from a DNS name of a node.
func ToBaseName(name string) string {
	if i := strings.Index(name, "."); i != -1 {
		return name[:i]
	}
	return name
}
