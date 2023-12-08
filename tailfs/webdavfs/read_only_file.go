// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

type readOnlyFile struct {
	io.ReadCloser
	fi fs.FileInfo
}

// Readdir implements webdav.File.
func (f *readOnlyFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{
		Op:   "readdir",
		Path: f.fi.Name(),
		Err:  errors.New("is a file"), // TODO(oxtoacart): make sure this and below errors match what a regular os.File does
	}
}

// Seek implements webdav.File.
func (f *readOnlyFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekEnd:
		// seek to end is usually done to check size, let's play along
		return f.fi.Size(), nil
	case io.SeekStart:
		if offset == 0 {
			// this is usually done to start reading after getting size
			return 0, nil
		}
	}

	// unknown seek scenario, error out
	return 0, &os.PathError{
		Op:   "seek",
		Path: f.fi.Name(),
		Err:  errors.New("seek not supported"),
	}
}

// Stat implements webdav.File.
func (f *readOnlyFile) Stat() (fs.FileInfo, error) {
	return f.fi, nil
}

// Write implements webdav.File.
func (f *readOnlyFile) Write(p []byte) (n int, err error) {
	return 0, &os.PathError{
		Op:   "write",
		Path: f.fi.Name(),
		Err:  errors.New("read-only"),
	}
}
