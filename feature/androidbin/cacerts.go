// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package androidbin

import "os"

// Android keeps its CA roots in /system/etc/security/cacerts as PEM
// files, a path Go's crypto/x509 knows about in GOOS=android builds
// but not GOOS=linux ones, so a linux binary on Android has an empty
// system cert pool and all TLS verification fails. Point Go's unix
// root loader there via SSL_CERT_DIR, which it honors on linux. This
// runs at init, before crypto/x509 lazily loads roots on first use.
//
// If the user already configured SSL_CERT_DIR or SSL_CERT_FILE (as
// Termux does when its ca-certificates package is installed), leave
// their configuration alone.
func init() {
	if !onAndroid() {
		return
	}
	if os.Getenv("SSL_CERT_DIR") != "" || os.Getenv("SSL_CERT_FILE") != "" {
		return
	}
	if fi, err := os.Stat(androidCACertDir); err != nil || !fi.IsDir() {
		return
	}
	os.Setenv("SSL_CERT_DIR", androidCACertDir)
}

const androidCACertDir = "/system/etc/security/cacerts"
