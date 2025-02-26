// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build generic

package sparse

import (
	"os"
)

// Calls the generic pucnhAt
// It just zeros out the file from the offset for the size bites.
func punchAt(fd *os.File, off, size int64) error {
	return punchAtGeneric(fd, off, size)
}
