// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"errors"
	"io/fs"
	"os"
)

type directoryFile struct {
	fi       fs.FileInfo
	children []fs.FileInfo
}

// Readdir implements webdav.File.
func (f *directoryFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{
		Op:   "readdir",
		Path: f.fi.Name(),
		Err:  errors.New("is a file"), // TODO(oxtoacart): make sure this and below errors match what a regular os.File does
	}
}

// Seek implements webdav.File.
func (f *directoryFile) Seek(offset int64, whence int) (int64, error) {
	return 0, &os.PathError{
		Op:   "readdir",
		Path: f.fi.Name(),
		Err:  errors.New("seek not supported"),
	}
}

// Stat implements webdav.File.
func (f *directoryFile) Stat() (fs.FileInfo, error) {
	return f.fi, nil
}

// Write implements webdav.File.
func (f *directoryFile) Write(p []byte) (n int, err error) {
	return 0, &os.PathError{
		Op:   "readdir",
		Path: f.fi.Name(),
		Err:  errors.New("read-only"),
	}
}
