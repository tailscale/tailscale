// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (android && !cgo)

package androiddns

import (
	"net"
	"os"
	"runtime"
)

// This init runs in GOOS=android builds without cgo and in all
// GOOS=linux builds, because static linux binaries (such as our
// official arm64 release tarballs) also run under Android kernels,
// commonly via Termux or a rooted shell, and have the same broken
// resolver there. Android builds with cgo enabled, including the
// Tailscale Android app, use Go's cgo resolver, which reaches the
// same daemon via bionic's getaddrinfo and needs no help.
//
// On an actual Linux system, /etc/resolv.conf exists and this is a
// no-op after one stat. Otherwise it requires positive evidence of
// Android (see onAndroid) plus a successful connection to the
// dnsproxyd socket before touching the default resolver.
func init() {
	if resolvConfExists() || !onAndroid() || !available() {
		return
	}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = resolverDial
}

// onAndroid reports whether the process is running on Android, even
// if it's a GOOS=linux binary running under an Android kernel. For
// that case it checks for /dev/__properties__, the bionic property
// service's backing store, which has existed on every Android version
// since 5.0, is stat-able by all processes because every app's libc
// reads properties, and is never present on regular Linux systems.
func onAndroid() bool {
	if runtime.GOOS == "android" {
		return true
	}
	_, err := os.Stat("/dev/__properties__")
	return err == nil
}
