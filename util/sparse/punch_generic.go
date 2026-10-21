// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin && !windows

package sparse

import (
	"io"
	"os"
)

// punchAt just calls [writeZeros] in the generic case.
func punchAt(fd *os.File, off, size int64) error {
	return writeZeros(fd, off, size)
}

// The generic unix implementation does not use sparse files.
// It just zeros out the file from the offset for the size bites.
func writeZeros(fd *os.File, off, size int64) error {
	_, err := fd.Seek(off, io.SeekStart)
	if err != nil {
		return err
	}
	zeros := make([]byte, size)
	_, err = fd.Write(zeros)
	return err
}
