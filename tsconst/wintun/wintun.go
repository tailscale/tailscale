// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wintun is the single source of truth for the pinned wintun.dll release
// the Tailscale Windows client is built and tested against.
package wintun

const (
	// Version is the pinned wintun release.
	Version = "0.14.1"
	// URL is the wintun.net download for Version.
	URL = "https://www.wintun.net/builds/wintun-" + Version + ".zip"
	// SHA256 is the hex-encoded sha256 of the zip at URL.
	SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
)

// DLLZipPath returns the path of the wintun.dll for goArch within the release zip.
func DLLZipPath(goArch string) string {
	arch := goArch
	if goArch == "386" {
		arch = "x86"
	}
	return "wintun/bin/" + arch + "/wintun.dll"
}
