// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cibuild reports runtime CI information.
package cibuild

import "os"

// On reports whether the current binary is executing on a CI system.
func On() bool {
	return os.Getenv("GITHUB_ACTIONS") != ""
}
