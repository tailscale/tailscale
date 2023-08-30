// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !wasm && !plan9 && !tamago

package logger

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func rusageMaxRSS() float64 {
	var ru unix.Rusage
	err := unix.Getrusage(unix.RUSAGE_SELF, &ru)
	if err != nil {
		return 0
	}

	rss := float64(ru.Maxrss)
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		rss /= 1 << 20 // ru_maxrss is bytes on darwin
	} else {
		// ru_maxrss is kilobytes elsewhere (linux, openbsd, etc)
		rss /= 1 << 10
	}
	return rss
}
