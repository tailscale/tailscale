// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
package netns

import "net"

// Listener returns a new net.Listener with its Control hook func
// initialized as necessary to run in logical network namespace that
// doesn't route back into Tailscale.
func Listener() *net.ListenConfig {
	return &net.ListenConfig{Control: control}
}

// Dialer returns a new net.Dialer with its Control hook func
// initialized as necessary to run in a logical network namespace that
// doesn't route back into Tailscale.
func Dialer() *net.Dialer {
	return &net.Dialer{Control: control}
}
