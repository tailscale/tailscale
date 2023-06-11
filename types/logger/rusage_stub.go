// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || js || wasip1

package logger

func rusageMaxRSS() float64 {
	// TODO(apenwarr): Substitute Windows equivalent of Getrusage() here.
	return 0
}
