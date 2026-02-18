// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package hostinfo

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"tailscale.com/types/ptr"
)

func init() {
	osVersion = lazyOSVersion.Get
	packageType = packageTypeDarwin
}

var (
	lazyOSVersion = &lazyAtomicValue[string]{f: ptr.To(osVersionDarwin)}
)

func packageTypeDarwin() string {
	// Using tailscaled or IPNExtension?
	exe, _ := os.Executable()
	return filepath.Base(exe)
}

// Returns the marketing version (e.g., "15.0.1" or "26.0.0")
func osVersionDarwin() string {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return version
}
