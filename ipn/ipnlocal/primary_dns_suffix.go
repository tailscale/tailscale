// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package ipnlocal

// primaryDNSSuffix returns the device's primary DNS suffix.
// On non-Windows platforms, this is not applicable and returns an empty string.
func primaryDNSSuffix() string {
	return ""
}
