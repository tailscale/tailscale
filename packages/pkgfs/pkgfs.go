// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkgfs implements a read-write filesystem abstraction for
// use by the package repository generation logic. It is not intended
// as a fully generic read-write FS abstraction, do not use outside of
// the package repository logic.
package pkgfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// A CreateFS is a file system with a Create method.
type CreateFS interface {
	// Create creates or truncates the file for writing.
	Create(name string, mode fs.FileMode) (io.WriteCloser, error)
}

// Create creates or truncates the named file. If the file already
// exists, it is truncated. If the file does not exist, it is
// created with the given mode.
func Create(fs fs.FS, name string, mode fs.FileMode) (io.WriteCloser, error) {
	wf, ok := fs.(CreateFS)
	if !ok {
		return nil, errors.New("read-only filesystem")
	}

	return wf.Create(name, mode)
}

// DirFS is like os.DirFS, but returns an FS that implements CreateFS.
func DirFS(dir string) fs.FS {
	return dirFS{
		FS:  os.DirFS(dir),
		dir: dir,
	}
}

type dirFS struct {
	fs.FS
	dir string
}

func (d dirFS) Create(name string, mode fs.FileMode) (io.WriteCloser, error) {
	if !fs.ValidPath(name) {
		return nil, &os.PathError{Op: "create", Path: name, Err: os.ErrInvalid}
	}
	return os.OpenFile(filepath.Join(d.dir, name), os.O_RDWR|os.O_CREATE, os.FileMode(mode))
}
