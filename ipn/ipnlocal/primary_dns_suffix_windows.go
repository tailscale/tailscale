// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import "tailscale.com/util/winutil/winenv"

// primaryDNSSuffix returns the device's primary DNS suffix, which on
// domain-joined Windows devices is the AD domain name (e.g., "corp.example.com").
// Returns an empty string if the device is not domain-joined or on error.
func primaryDNSSuffix() string {
	return winenv.DomainName()
}
