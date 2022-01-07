// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version provides the version that the binary was built at.
package version

import (
	"strings"

	tailscaleroot "tailscale.com"
)

// Long is a full version number for this build, of the form
// "x.y.z-commithash", or "date.yyyymmdd" if no actual version was
// provided.
var Long = "date.20220107"

// Short is a short version number for this build, of the form
// "x.y.z", or "date.yyyymmdd" if no actual version was provided.
var Short = ""

func init() {
	// If it hasn't been link-stamped with -X (via build_dist.sh or similar),
	// then use the VERSION.txt file in the root and the date in the Long
	// variable above which we occasionally bump by hand.
	if Short == "" {
		Long = strings.TrimSpace(tailscaleroot.Version) + "-" + Long
		Short = Long
	}
}

// GitCommit, if non-empty, is the git commit of the
// github.com/tailscale/tailscale repository at which Tailscale was
// built. Its format is the one returned by `git describe --always
// --exclude "*" --dirty --abbrev=200`.
var GitCommit = ""

// ExtraGitCommit, if non-empty, is the git commit of a "supplemental"
// repository at which Tailscale was built. Its format is the same as
// gitCommit.
//
// ExtraGitCommit is used to track the source revision when the main
// Tailscale repository is integrated into and built from another
// repository (for example, Tailscale's proprietary code, or the
// Android OSS repository). Together, GitCommit and ExtraGitCommit
// exactly describe what repositories and commits were used in a
// build.
var ExtraGitCommit = ""
