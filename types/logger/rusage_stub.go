// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || js

package logger

func rusageMaxRSS() float64 {
	// TODO(apenwarr): Substitute Windows equivalent of Getrusage() here.
	return 0
}
