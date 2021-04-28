// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"os"
	"runtime"
	"strings"
)

// IsMobile reports whether this is a mobile client build.
func IsMobile() bool {
	return runtime.GOOS == "android" || runtime.GOOS == "ios"
}

// OS returns runtime.GOOS, except instead of returning "darwin" it
// returns "iOS" or "macOS".
func OS() string {
	if runtime.GOOS == "ios" {
		return "iOS"
	}
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	return runtime.GOOS
}

// IsSandboxedMacOS reports whether this process is a sandboxed macOS
// (GUI) process. It is true for the Mac App Store and macsys (System
// Extension) version on macOS, and false for tailscaled-on-macOS.
func IsSandboxedMacOS() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	exe, _ := os.Executable()
	return strings.HasSuffix(exe, "/Contents/MacOS/Tailscale")
}
