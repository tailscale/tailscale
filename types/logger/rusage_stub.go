// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || wasm || plan9 || tamago

package logger

func rusageMaxRSS() float64 {
	// TODO(apenwarr): Substitute Windows equivalent of Getrusage() here.
	return 0
}
