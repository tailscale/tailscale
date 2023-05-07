// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package version provides the version that the binary was built at.
package version

import (
	"fmt"
	"runtime/debug"
	"strings"

	tailscaleroot "tailscale.com"
	"tailscale.com/types/lazy"
)

// Stamp vars can have their value set at build time by linker flags (see
// build_dist.sh for an example). When set, these stamps serve as additional
// inputs to computing the binary's version as returned by the functions in this
// package.
//
// All stamps are optional.
var (
	// longStamp is the full version identifier of the build. If set, it is
	// returned verbatim by Long() and other functions that return Long()'s
	// output.
	longStamp string

	// shortStamp is the short version identifier of the build. If set, it
	// is returned verbatim by Short() and other functions that return Short()'s
	// output.
	shortStamp string

	// gitCommitStamp is the git commit of the github.com/tailscale/tailscale
	// repository at which Tailscale was built. Its format is the one returned
	// by `git rev-parse <commit>`. If set, it is used instead of any git commit
	// information embedded by the Go tool.
	gitCommitStamp string

	// gitDirtyStamp is whether the git checkout from which the code was built
	// was dirty. Its value is ORed with the dirty bit embedded by the Go tool.
	//
	// We need this because when we build binaries from another repo that
	// imports tailscale.com, the Go tool doesn't stamp any dirtiness info into
	// the binary. Instead, we have to inject the dirty bit ourselves here.
	gitDirtyStamp bool

	// extraGitCommit, is the git commit of a "supplemental" repository at which
	// Tailscale was built. Its format is the same as gitCommit.
	//
	// extraGitCommit is used to track the source revision when the main
	// Tailscale repository is integrated into and built from another repository
	// (for example, Tailscale's proprietary code, or the Android OSS
	// repository). Together, gitCommit and extraGitCommit exactly describe what
	// repositories and commits were used in a build.
	extraGitCommitStamp string
)

var long lazy.SyncValue[string]

// Long returns a full version number for this build, of one of the forms:
//
//   - "x.y.z-commithash-otherhash" for release builds distributed by Tailscale
//   - "x.y.z-commithash" for release builds built with build_dist.sh
//   - "x.y.z-changecount-commithash-otherhash" for untagged release branch
//     builds by Tailscale (these are not distributed).
//   - "x.y.z-changecount-commithash" for untagged release branch builds
//     built with build_dist.sh
//   - "x.y.z-devYYYYMMDD-commithash{,-dirty}" for builds made with plain "go
//     build" or "go install"
//   - "x.y.z-ERR-BuildInfo" for builds made by plain "go run"
func Long() string {
	return long.Get(func() string {
		if longStamp != "" {
			return longStamp
		}
		bi := getEmbeddedInfo()
		if !bi.valid {
			return strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-ERR-BuildInfo"
		}
		return fmt.Sprintf("%s-dev%s-t%s%s", strings.TrimSpace(tailscaleroot.VersionDotTxt), bi.commitDate, bi.commitAbbrev(), dirtyString())
	})
}

var short lazy.SyncValue[string]

// Short returns a short version number for this build, of the forms:
//
//   - "x.y.z" for builds distributed by Tailscale or built with build_dist.sh
//   - "x.y.z-devYYYYMMDD" for builds made with plain "go build" or "go install"
//   - "x.y.z-ERR-BuildInfo" for builds made by plain "go run"
func Short() string {
	return short.Get(func() string {
		if shortStamp != "" {
			return shortStamp
		}
		bi := getEmbeddedInfo()
		if !bi.valid {
			return strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-ERR-BuildInfo"
		}
		return strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-dev" + bi.commitDate
	})
}

type embeddedInfo struct {
	valid      bool
	commit     string
	commitDate string
	dirty      bool
}

func (i embeddedInfo) commitAbbrev() string {
	if len(i.commit) >= 9 {
		return i.commit[:9]
	}
	return i.commit
}

var getEmbeddedInfo = lazy.SyncFunc(func() embeddedInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return embeddedInfo{}
	}
	ret := embeddedInfo{valid: true}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			ret.commit = s.Value
		case "vcs.time":
			if len(s.Value) >= len("yyyy-mm-dd") {
				ret.commitDate = s.Value[:len("yyyy-mm-dd")]
				ret.commitDate = strings.ReplaceAll(ret.commitDate, "-", "")
			}
		case "vcs.modified":
			ret.dirty = s.Value == "true"
		}
	}
	if ret.commit == "" || ret.commitDate == "" {
		// Build info is present in the binary, but has no useful data. Act as
		// if it's missing.
		return embeddedInfo{}
	}
	return ret
})

func gitCommit() string {
	if gitCommitStamp != "" {
		return gitCommitStamp
	}
	return getEmbeddedInfo().commit
}

func gitDirty() bool {
	if gitDirtyStamp {
		return true
	}
	return getEmbeddedInfo().dirty
}

func dirtyString() string {
	if gitDirty() {
		return "-dirty"
	}
	return ""
}

func majorMinorPatch() string {
	ret, _, _ := strings.Cut(Short(), "-")
	return ret
}
