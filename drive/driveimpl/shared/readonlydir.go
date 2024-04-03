// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package shared contains types and functions shared by different drive
// packages.
package shared

import (
	"errors"
	"io"
	"io/fs"
	"sync"
)

// DirFile implements webdav.File for a virtual directory.
// It mimics the behavior of an os.File that is pointing at a real directory.
type DirFile struct {
	// Info provides the fs.FileInfo for this directory
	Info fs.FileInfo
	// LoadChildren is used to load the fs.FileInfos for this directory's
	// children. It is called at most once in order to support listing
	// children.
	LoadChildren func() ([]fs.FileInfo, error)

	// loadChildrenMu guards children and loadedChildren.
	loadChildrenMu sync.Mutex
	children       []fs.FileInfo
	loadedChildren bool
}

// Readdir implements interface webdav.File. It lazily loads information about
// children when it is called.
func (d *DirFile) Readdir(count int) ([]fs.FileInfo, error) {
	err := d.loadChildrenIfNecessary()
	if err != nil {
		return nil, err
	}

	if count <= 0 {
		result := d.children
		d.children = nil
		return result, nil
	}

	n := len(d.children)
	if count < n {
		n = count
	}
	result := d.children[:n]
	d.children = d.children[n:]
	if len(d.children) == 0 {
		err = io.EOF
	}
	return result, err
}

func (d *DirFile) loadChildrenIfNecessary() error {
	d.loadChildrenMu.Lock()
	defer d.loadChildrenMu.Unlock()

	if !d.loadedChildren {
		var err error
		d.children, err = d.LoadChildren()
		if err != nil {
			return err
		}
		d.loadedChildren = true
	}
	return nil
}

// Stat implements interface webdav.File.
func (d *DirFile) Stat() (fs.FileInfo, error) {
	return d.Info, nil
}

// Close implements interface webdav.File. It does nothing and never returns an
// error.
func (d *DirFile) Close() error {
	return nil
}

// Read implements interface webdav.File. As this is a directory, it always
// fails with an fs.PathError.
func (d *DirFile) Read(b []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "read",
		Path: d.Info.Name(),
		Err:  errors.New("is a directory"),
	}
}

// Write implements interface webdav.File. As this is a directory, it always
// fails with an fs.PathError.
func (d *DirFile) Write(b []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "write",
		Path: d.Info.Name(),
		Err:  errors.New("bad file descriptor"),
	}
}

// Seek implements interface webdav.File. As this is a directory, it always
// fails with an fs.PathError.
func (d *DirFile) Seek(offset int64, whence int) (int64, error) {
	return 0, &fs.PathError{
		Op:   "seek",
		Path: d.Info.Name(),
		Err:  errors.New("invalid argument"),
	}
}
