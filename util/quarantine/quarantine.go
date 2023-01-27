// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package quarantine sets platform specific "quarantine" attributes on files
// that are received from other hosts.
package quarantine

import "os"

// SetOnFile sets the platform-specific quarantine attribute (if any) on the
// provided file.
func SetOnFile(f *os.File) error {
	return setQuarantineAttr(f)
}
