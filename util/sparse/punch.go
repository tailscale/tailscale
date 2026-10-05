// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sparse contains some helpful generic sparse file functions.
package sparse

import (
	"os"
)

// PunchAt takes an os.File and offset and size as int64 to punch
// a hole in a sparse file.
func PunchAt(fd *os.File, off, size int64) error {
	return punchAt(fd, off, size)
}
