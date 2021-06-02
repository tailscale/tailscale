// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version provides the version that the binary was built at.
package version

// Long is a full version number for this build, of the form
// "x.y.z-commithash", or "date.yyyymmdd" if no actual version was
// provided.
var Long = "date.20210505"

// Short is a short version number for this build, of the form
// "x.y.z", or "date.yyyymmdd" if no actual version was provided.
var Short = Long

// LONG is a deprecated alias for Long. Don't use it.
var LONG = Long

// SHORT is a deprecated alias for Short. Don't use it.
var SHORT = Short

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
