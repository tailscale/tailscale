// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version provides the version that the binary was built at.
package version

import (
	"runtime/debug"
	"strings"

	tailscaleroot "tailscale.com"
)

// Long is a full version number for this build, of the form
// "x.y.z-commithash" for builds stamped in the usual way (see
// build_dist.sh in the root) or, for binaries built by hand with the
// go tool, it's of the form "1.23.0-dev20220316-t29837428937{,-dirty}"
// where "1.23.0" comes from ../VERSION.txt and the part after dev
// is YYYYMMDD of the commit time, and the part after -t is the commit
// hash. The dirty suffix is whether there are uncommitted changes.
var Long = ""

// Short is a short version number for this build, of the form
// "x.y.z" for builds stamped in the usual way (see
// build_dist.sh in the root) or, for binaries built by hand with the
// go tool, it's like Long's dev form, but ending at the date part,
// of the form "1.23.0-dev20220316".
var Short = ""

func init() {
	if Long != "" && Short != "" {
		// Built in the recommended way, using build_dist.sh.
		return
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		Long = strings.TrimSpace(tailscaleroot.Version) + "-ERR-BuildInfo"
		Short = Long
		return
	}
	var dirty string // "-dirty" suffix if dirty
	var commitDate string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			GitCommit = s.Value
		case "vcs.time":
			if len(s.Value) >= len("yyyy-mm-dd") {
				commitDate = s.Value[:len("yyyy-mm-dd")]
				commitDate = strings.ReplaceAll(commitDate, "-", "")
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
				GitDirty = true
			}
		}
	}
	commitHashAbbrev := GitCommit
	if len(commitHashAbbrev) >= 9 {
		commitHashAbbrev = commitHashAbbrev[:9]
	}

	// Backup path, using Go 1.18's built-in git stamping.
	Short = strings.TrimSpace(tailscaleroot.Version) + "-dev" + commitDate
	Long = Short + "-t" + commitHashAbbrev + dirty
}

// GitCommit, if non-empty, is the git commit of the
// github.com/tailscale/tailscale repository at which Tailscale was
// built. Its format is the one returned by `git describe --always
// --exclude "*" --dirty --abbrev=200`.
var GitCommit = ""

// GitDirty is whether Go stamped the binary as having dirty version
// control changes in the working directory (debug.ReadBuildInfo
// setting "vcs.modified" was true).
var GitDirty bool

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
