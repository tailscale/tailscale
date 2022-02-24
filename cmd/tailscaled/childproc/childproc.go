// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package childproc allows other packages to register "tailscaled be-child"
// child process hook code. This avoids duplicating build tags in the
// tailscaled package. Instead, the code that needs to fork/exec the self
// executable (when it's tailscaled) can instead register the code
// they want to run.
package childproc

var Code = map[string]func([]string) error{}

// Add registers code f to run as 'tailscaled be-child <typ> [args]'.
func Add(typ string, f func(args []string) error) {
	if _, dup := Code[typ]; dup {
		panic("dup hook " + typ)
	}
	Code[typ] = f
}
