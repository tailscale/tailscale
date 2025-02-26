// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !linux && !darwin

package sparse

import "os"

// punchAt for generic unix will just use punchAtGeneric
func punchAt(fd *os.File, off, size int64) error {
	return punchAtGeneric(fd, off, size)
}
