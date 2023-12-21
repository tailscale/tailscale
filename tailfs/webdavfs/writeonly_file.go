// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"

	"tailscale.com/tailfs/shared"
)

type writeOnlyFile struct {
	io.WriteCloser
	name       string
	perm       os.FileMode
	fs         *webdavFS
	finalError chan error
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
		now := f.fs.now()
		fi = &shared.StaticFileInfo{
			Named:       f.name,
			Sized:       0,
			Moded:       f.perm,
			BirthedTime: now,
			ModdedTime:  now,
			Dir:         false,
		}
	}
	return fi, nil
}

// Read implements webdav.File.
func (f *writeOnlyFile) Read(p []byte) (int, error) {
	return 0, &os.PathError{
		Op:   "write",
		Path: f.name,
		Err:  errors.New("write-only"),
	}
}

// Write implements webdav.File.
func (f *writeOnlyFile) Write(p []byte) (int, error) {
	select {
	case err := <-f.finalError:
		return 0, err
	default:
		return f.WriteCloser.Write(p)
	}
}

// Close implements webdav.File
func (f *writeOnlyFile) Close() error {
	err := f.WriteCloser.Close()
	writeErr := <-f.finalError
	if writeErr != nil {
		return writeErr
	}
	return err
}
