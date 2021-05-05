// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkgfstest implements a testing-only writable in-memory
// filesystem.
package pkgfstest

import (
	"io"
	"io/fs"
	"testing/fstest"
)

// A MapFS is an in-memory file system like fstest.MapFS, but that
// also implements CreateFS, making it read-write.
//
// MapFS is not generally safe for concurrent access. Multiple fs.FS
// readers may operate concurrently, but all other operations (writes,
// manual changes to the map) must be serialized by the caller.
type MapFS map[string]*fstest.MapFile

// Open implements fs.FS.
func (fsys MapFS) Open(name string) (fs.File, error) {
	return (fstest.MapFS)(fsys).Open(name)
}

// Create implements pkgfs.CreateFS
func (fsys MapFS) Create(name string, mode fs.FileMode) (io.WriteCloser, error) {
	mf := &fstest.MapFile{
		Mode: mode,
		// Create time deliberately zero to make comparisons in tests easier
	}
	fsys[name] = mf
	return (*writer)(mf), nil
}

type writer fstest.MapFile

func (w *writer) Write(bs []byte) (int, error) {
	mf := (*fstest.MapFile)(w)
	mf.Data = append(mf.Data, bs...)
	return len(bs), nil
}

func (w *writer) Close() error {
	return nil
}
