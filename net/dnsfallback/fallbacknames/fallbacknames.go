// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package fallbacknames defines which hostnames the DERP-based fallback
// DNS mechanism (net/dnsfallback and the DERP server's /bootstrap-dns
// handler) is allowed to resolve.
//
// It's a leaf package so that both clients and cmd/derper can share the
// policy without depending on each other.
//
// We're slowly removing the DERP-based fallback DNS mechanism entirely in
// favor of caching earlier DNS results on disk (feature/dnsresolvecache).
// This set of names may shrink over time but must not grow.
// See https://github.com/tailscale/tailscale/issues/21028.
package fallbacknames

import "strings"

// IsTailscaleHost reports whether host is one of Tailscale's own hostnames,
// the only names the DERP-based fallback DNS resolves.
func IsTailscaleHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !validHostname(host) {
		return false
	}
	return host == "tailscale.com" ||
		strings.HasSuffix(host, ".tailscale.com") ||
		strings.HasSuffix(host, ".tailscale.io")
}

// validHostname reports whether host is made of non-empty dot-separated
// labels of lowercase letters, digits, and hyphens.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" {
			return false
		}
		for _, c := range label {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
