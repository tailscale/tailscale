// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package shared contains components shared by different tailfs packages
package shared

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"
	"time"
)

// DirFile implements webdav.File for a directory.
// It mimics the behavior of an os.File that is pointing at a real directory.
type DirFile struct {
	Info           fs.FileInfo
	LoadChildren   func() ([]fs.FileInfo, error)
	children       []fs.FileInfo
	loadedChildren bool
	loadChildrenMx sync.Mutex
}

func (d *DirFile) Readdir(count int) ([]fs.FileInfo, error) {
	fmt.Println("ZZZZ here")
	err := d.loadChildrenIfNecessary()
	if err != nil {
		fmt.Printf("ZZZZ error loading children: %v\n", err)
		return nil, err
	}

	if count <= 0 {
		result := d.children
		fmt.Printf("ZZZZ returning with number of children %d\n", len(d.children))
		d.children = nil
		return result, nil
	}

	fmt.Printf("ZZZZ number of children %d\n", len(d.children))
	n := len(d.children)
	if count < n {
		n = count
	}
	result := d.children[:n]
	fmt.Printf("ZZZZ number of result children %d\n", len(result))
	d.children = d.children[n:]
	if len(d.children) == 0 {
		err = io.EOF
	}
	return result, err
}

func (d *DirFile) loadChildrenIfNecessary() error {
	d.loadChildrenMx.Lock()
	defer d.loadChildrenMx.Unlock()

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

func (d *DirFile) Stat() (fs.FileInfo, error) {
	return d.Info, nil
}

func (d *DirFile) Close() error {
	return nil
}

func (d *DirFile) Read(b []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "read",
		Path: d.Info.Name(),
		Err:  errors.New("is a directory"),
	}
}

func (d *DirFile) Write(b []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "write",
		Path: d.Info.Name(),
		Err:  errors.New("bad file descriptor"),
	}
}

func (d *DirFile) Seek(offset int64, whence int) (int64, error) {
	return 0, &fs.PathError{
		Op:   "seek",
		Path: d.Info.Name(),
		Err:  errors.New("invalid argument"),
	}
}

func eadOnlyDirInfo(name string) fs.FileInfo {
	return &StaticFileInfo{
		Named:    name,
		Sized:    0,
		Moded:    modeReadOnlyDir,
		ModTimed: time.Time{},
		Dir:      true,
	}
}
