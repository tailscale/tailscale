// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sparse contains some helpful generic sparse file functions.
package sparse

import (
	"io"
	"os"
)

// PunchAt takes an os.File and offset and size as int64 to punch
// a hole in a sparse file.
func PunchAt(fd *os.File, off, size int64) error {
	return punchAt(fd, off, size)
}

// The generic unix implementation does not use sparse files.
// It just zeros out the file from the offset for the size bites.
//
//lint:ignore U1000 This is used by only two operating systems.
func punchAtGeneric(fd *os.File, off, size int64) error {
	_, err := fd.Seek(off, io.SeekStart)
	if err != nil {
		return err
	}
	zeros := make([]byte, size)
	_, err = fd.Write(zeros)
	if err != nil {
		return err
	}
	return nil
}
