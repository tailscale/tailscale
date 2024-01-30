// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import "regexp"

// isMagicDNSName reports whether name is a full tailnet node FQDN (with or
// without final dot).
func IsMagicDNSName(name string) bool {
	validMagicDNSName := regexp.MustCompile(`^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.ts\.net\.?$`)
	return validMagicDNSName.MatchString(name)
}
