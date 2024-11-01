// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.20

// Package fallback embeds a set of fallback X.509 trusted roots in the
// application by automatically invoking [x509.SetFallbackRoots]. This allows
// the application to work correctly even if the operating system does not
// provide a verifier or system roots pool.
//
// To use it, import the package like
//
//	import _ "golang.org/x/crypto/x509roots/fallback"
//
// It's recommended that only binaries, and not libraries, import this package.
//
// This package must be kept up to date for security and compatibility reasons.
// Use govulncheck to be notified of when new versions of the package are
// available.
package fallback

import "crypto/x509"

func init() {
	p := x509.NewCertPool()
	for _, c := range bundle {
		p.AddCert(c)
	}
	x509.SetFallbackRoots(p)
}
