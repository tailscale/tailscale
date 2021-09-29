// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Packate updates is an evalator for a update policy file that controls
// when users get update available notifications (and which types).
//
// It's used and hot reloaded by several servers. It permits us to
// centralize and test the update policy.
package updates

type Policy struct {
	Tests []*Test
	Rules []*Rule
}

type Test struct {
	OS     string
	Distro string // "synology" on Linux
	Ver    string // "1.2.3-tXXXX-gXXX"
	Want   string // "", "update", "update/security"
}

type Rule struct {
	// Ver, if non-empty, matches the version number.
	// If it begins with an operator ("<", "<=", then the comparison
	// is done semantically based on semver, not lexically.
	Ver string

	// OS, if non-empty, matches the node operating system.
	// Possible values: "linux", "windows", "macOS", "iOS", or
	// else a runtime.GOOS value (except not "darwin" or "ios").
	OS string

	// Package, if non-empty, matches the packaging variant.
	// Possible values: "choco", "appstore", "macsys", "tailscaled".
	Package string

	// Distro, if non-empty, matches the node's distro.
	// Possible values: "synology".
	Distro string

	// Now, if non-empty, matches based on the current date in UTC.
	// e.g. ">=2021-10-07".
	Now string

	Then      string // "stop", "update", "update/security", "update: note"
	ThenRules []*Rule
	ElseRules []*Rule
}
