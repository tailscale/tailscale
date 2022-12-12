// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package quarantine sets platform specific "quarantine" attributes on files
// that are received from other hosts.
package quarantine

import "os"

// SetOnFile sets the platform-specific quarantine attribute (if any) on the
// provided file.
func SetOnFile(f *os.File) error {
	return setQuarantineAttr(f)
}
