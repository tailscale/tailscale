// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"time"

	"golang.org/x/net/webdav"
	"tailscale.com/tailfs/shared"
)

type writeOnlyFile struct {
	io.WriteCloser
	name  string
	perm  os.FileMode
	fs    webdav.FileSystem
	errCh chan<- error
}

// Readdir implements webdav.File.
func (f *writeOnlyFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{
		Op:   "readdir",
		Path: f.name,
		Err:  errors.New("is a file"), // TODO(oxtoacart): make sure this and below errors match what a regular os.File does
	}
}

// Seek implements webdav.File.
func (f *writeOnlyFile) Seek(offset int64, whence int) (int64, error) {
	return 0, &os.PathError{
		Op:   "seek",
		Path: f.name,
		Err:  errors.New("seek not supported"),
	}
}

// Stat implements webdav.File.
func (f *writeOnlyFile) Stat() (fs.FileInfo, error) {
	fi, err := f.fs.Stat(context.Background(), f.name)
	if err != nil {
		// use static info for newly created file
		fi = &shared.StaticFileInfo{
			Named:    f.name,
			Sized:    0,
			Moded:    f.perm,
			ModTimed: time.Now(),
			Dir:      false,
		}
	}
	return fi, nil
}

// Write implements webdav.File.
func (f *writeOnlyFile) Read(p []byte) (n int, err error) {
	return 0, &os.PathError{
		Op:   "write",
		Path: f.name,
		Err:  errors.New("write-only"),
	}
}
