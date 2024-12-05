// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netknob has Tailscale network knobs.
package netknob

import (
	"runtime"
	"time"
)

// PlatformTCPKeepAlive returns the default net.Dialer.KeepAlive
// value for the current runtime.GOOS.
func PlatformTCPKeepAlive() time.Duration {
	switch runtime.GOOS {
	case "ios", "android":
		// Disable TCP keep-alives on mobile platforms.
		// See https://github.com/golang/go/issues/48622.
		//
		// TODO(bradfitz): in 1.17.x, try disabling TCP
		// keep-alives on for all platforms.
		return -1
	}

	// Otherwise, default to 30 seconds, which is mostly what we
	// used to do. In some places we used the zero value, which Go
	// defaults to 15 seconds. But 30 seconds is fine.
	return 30 * time.Second
}
