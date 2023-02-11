// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package version provides the version that the binary was built at.
package version

import (
	"runtime/debug"
	"strings"

	tailscaleroot "tailscale.com"
)

var long = ""

var short = ""

// Long is a full version number for this build, of the form
// "x.y.z-commithash" for builds stamped in the usual way (see
// build_dist.sh in the root) or, for binaries built by hand with the
// go tool, it's of the form "1.23.0-dev20220316-t29837428937{,-dirty}"
// where "1.23.0" comes from ../VERSION.txt and the part after dev
// is YYYYMMDD of the commit time, and the part after -t is the commit
// hash. The dirty suffix is whether there are uncommitted changes.
func Long() string {
	return long
}

// Short is a short version number for this build, of the form
// "x.y.z" for builds stamped in the usual way (see
// build_dist.sh in the root) or, for binaries built by hand with the
// go tool, it's like Long's dev form, but ending at the date part,
// of the form "1.23.0-dev20220316".
func Short() string {
	return short
}

func init() {
	defer func() {
		// Must be run after Short has been initialized, easiest way to do that
		// is a defer.
		majorMinorPatch, _, _ = strings.Cut(short, "-")
	}()

	if long != "" && short != "" {
		// Built in the recommended way, using build_dist.sh.
		return
	}

	// Otherwise, make approximate version info using Go 1.18's built-in git
	// stamping.
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		long = strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-ERR-BuildInfo"
		short = long
		return
	}
	var dirty string // "-dirty" suffix if dirty
	var commitDate string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			gitCommit = s.Value
		case "vcs.time":
			if len(s.Value) >= len("yyyy-mm-dd") {
				commitDate = s.Value[:len("yyyy-mm-dd")]
				commitDate = strings.ReplaceAll(commitDate, "-", "")
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
				gitDirty = true
			}
		}
	}
	commitHashAbbrev := gitCommit
	if len(commitHashAbbrev) >= 9 {
		commitHashAbbrev = commitHashAbbrev[:9]
	}

	// Backup path, using Go 1.18's built-in git stamping.
	short = strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-dev" + commitDate
	long = short + "-t" + commitHashAbbrev + dirty
}

// GitCommit, if non-empty, is the git commit of the
// github.com/tailscale/tailscale repository at which Tailscale was
// built. Its format is the one returned by `git describe --always
// --exclude "*" --dirty --abbrev=200`.
var gitCommit = ""

// GitDirty is whether Go stamped the binary as having dirty version
// control changes in the working directory (debug.ReadBuildInfo
// setting "vcs.modified" was true).
var gitDirty bool

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
var extraGitCommit = ""

// majorMinorPatch is the major.minor.patch portion of Short.
var majorMinorPatch string
