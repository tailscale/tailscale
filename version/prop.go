// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import "runtime"

// IsMobile reports whether this is a mobile client build.
func IsMobile() bool {
	// Good enough heuristic for now, at least until Apple makes
	// ARM laptops...
	return runtime.GOOS == "android" ||
		(runtime.GOOS == "darwin" && (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64"))
}
