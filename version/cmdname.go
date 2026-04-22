// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package version

import (
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// CmdName returns either the base name of the current binary
// using os.Executable. If os.Executable fails (it shouldn't), then
// "cmd" is returned.
//
// The result is computed once per process and cached. It is recovered
// from the Go module info embedded in the running binary via
// [runtime/debug.ReadBuildInfo], which reads an already-resident
// string maintained by the runtime; no filesystem I/O is performed.
// This is materially cheaper than inferring the command name from
// the on-disk executable, which was previously done by scanning the
// entire binary for magic bytes on every call. CmdName is called at
// least twice during tailscaled startup on Windows (by logpolicy).
func CmdName() string { return cmdNameCached() }

var cmdNameCached = sync.OnceValue(func() string {
	// fallbackName is derived from os.Executable and used if we cannot
	// recover a package path from the binary's embedded build info.
	var fallbackName string
	if e, err := os.Executable(); err == nil {
		fallbackName = prepExeNameForCmp(e, runtime.GOARCH)
	} else {
		fallbackName = "cmd"
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Path == "" {
		return fallbackName
	}
	// bi.Path is the main package import path, e.g.
	// "tailscale.com/cmd/tailscaled". Go import paths are always
	// forward-slash separated, so use path.Base, not filepath.Base.
	ret := path.Base(bi.Path)
	if runtime.GOOS == "windows" && strings.HasPrefix(ret, "gui") && checkPreppedExeNameForGUI(fallbackName) {
		// The GUI binary, for internal build-system packaging reasons,
		// has a path of "tailscale.io/win/gui". Ignore that name and
		// use fallbackName instead.
		return fallbackName
	}
	return ret
})
