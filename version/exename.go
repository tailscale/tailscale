// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"path/filepath"
	"strings"
)

// prepExeNameForCmp strips any extension and arch suffix from exe, and
// lowercases it.
func prepExeNameForCmp(exe, arch string) string {
	baseNoExt := strings.ToLower(strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe)))
	archSuffix := "-" + arch
	return strings.TrimSuffix(baseNoExt, archSuffix)
}

func checkPreppedExeNameForGUI(preppedExeName string) bool {
	return preppedExeName == "tailscale-ipn" || preppedExeName == "tailscale-gui"
}

func isGUIExeName(exe, arch string) bool {
	return checkPreppedExeNameForGUI(prepExeNameForCmp(exe, arch))
}
