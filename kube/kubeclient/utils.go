// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubeclient provides a client to interact with Kubernetes.
// This package is Tailscale-internal and not meant for external consumption.
// Further, the API should not be considered stable.
// Client is split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package kubeclient

import "strings"

// SanitizeKey converts any value that can be converted to a string into a valid Kubernetes Secret key.
// Valid characters are alphanumeric, -, _, and .
// https://kubernetes.io/docs/concepts/configuration/secret/#restriction-names-data.
func SanitizeKey[T ~string](k T) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, string(k))
}
