// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import "runtime"

// IsMobile reports whether this is a mobile client build.
func IsMobile() bool {
	// Good enough heuristic for now, at least until Apple makes
	// ARM laptops...
	return runtime.GOOS == "android" || isIOS
}

// OS returns runtime.GOOS, except instead of returning "darwin" it
// returns "iOS" or "macOS".
func OS() string {
	if isIOS {
		return "iOS"
	}
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	return runtime.GOOS
}
