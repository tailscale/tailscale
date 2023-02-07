// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package version provides the version that the binary was built at.
package version

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	tailscaleroot "tailscale.com"
)

var (
	// Long is a full version number for this build, of the form
	// "x.y.z-commithash" for builds stamped in the usual way (see build_dist.sh
	// in the root) or, for binaries built by hand with the go tool, it's of the
	// form "1.23.0-dev20220316-t29837428937{,-dirty}" where "1.23.0" comes from
	// ../VERSION.txt and the part after dev is YYYYMMDD of the commit time, and
	// the part after -t is the commit hash. The dirty suffix is whether there
	// are uncommitted changes.
	Long string

	// Short is a short version number for this build, of the form
	// "x.y.z" for builds stamped in the usual way (see
	// build_dist.sh in the root) or, for binaries built by hand with the
	// go tool, it's like Long's dev form, but ending at the date part,
	// of the form "1.23.0-dev20220316".
	Short string

	// GitCommit, if non-empty, is the git commit of the
	// github.com/tailscale/tailscale repository at which Tailscale was
	// built. Its format is the one returned by `git describe --always
	// --exclude "*" --dirty --abbrev=200`.
	GitCommit string

	// GitDirty is whether Go stamped the binary as having dirty version
	// control changes in the working directory (debug.ReadBuildInfo
	// setting "vcs.modified" was true).
	GitDirty bool

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
	ExtraGitCommit = ""

	// isUnstable is whether the current build appears to be an unstable, i.e. with
	// an odd minor version number.
	isUnstable bool

	// legacyOS is runtime.GOOS, except on apple devices where it's either "iOS" or
	// "macOS" (with that exact case).
	//
	// This used to be a thing because Go reported both macOS and iOS as "darwin"
	// and we needed to tell them apart. But then Go learned GOOS=ios and
	// GOOS=darwin as separate things, but we're still stuck with this function
	// because of the odd casing we picked, which has ossified into databases.
	legacyOS string

	// isMobile is whether the current build is for a mobile device.
	isMobile bool

	// isSandboxedMacOS is whether the current binary is any binary in the mac store
	// or standalone sysext mac apps.
	isSandboxedMacOS bool

	// isMacSysExt is whether the current binary is the mac system extension binary.
	isMacSysExt bool

	// isWindowsGUI is whether the current binary is the Windows GUI binary.
	isWindowsGUI bool
)

func init() {
	initVersion()
	initUnstable()
	initMiscTraits()
}

func initVersion() {
	if Long != "" && Short != "" {
		// Built in the recommended way, using build_dist.sh.
		return
	}

	// Otherwise, make approximate version info using Go 1.18's built-in git
	// stamping.
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

func initUnstable() {
	_, rest, ok := strings.Cut(Short, ".")
	if !ok {
		return
	}
	minorStr, _, ok := strings.Cut(rest, ".")
	if !ok {
		return
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return
	}
	isUnstable = minor%2 == 1
}

func initMiscTraits() {
	exe, _ := os.Executable()
	base := filepath.Base(exe)

	legacyOS = runtime.GOOS
	switch runtime.GOOS {
	case "darwin":
		legacyOS = "macOS"
		isMacSysExt = strings.HasPrefix(base, "io.tailscale.ipn.macsys.network-extension")
		isSandboxedMacOS = isMacSysExt || strings.HasSuffix(exe, "/Contents/MacOS/Tailscale") || strings.HasSuffix(exe, "/Contents/MacOS/IPNExtension")
	case "ios":
		legacyOS = "iOS"
		isMobile = true
	case "android":
		isMobile = true
	case "windows":
		isWindowsGUI = strings.EqualFold(base, "tailscale-ipn.exe") || strings.EqualFold(base, "tailscale-ipn")
	}
}
