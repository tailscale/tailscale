// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package shared

import (
	"io/fs"
	"os"
	"time"
)

const (
	modeReadOnlyDir = 0555
)

// StaticFileInfo implements a static fs.StaticFileInfo
type StaticFileInfo struct {
	// Named controls Name()
	Named string
	// Sized controls Size()
	Sized int64
	// Moded controls Mode()
	Moded os.FileMode
	// ModTimed controls ModTime()
	ModTimed time.Time
	// Dir controls IsDir()
	Dir bool
}

func (fi *StaticFileInfo) Name() string       { return fi.Named }
func (fi *StaticFileInfo) Size() int64        { return fi.Sized }
func (fi *StaticFileInfo) Mode() os.FileMode  { return fi.Moded }
func (fi *StaticFileInfo) ModTime() time.Time { return fi.ModTimed }
func (fi *StaticFileInfo) IsDir() bool        { return fi.Dir }
func (fi *StaticFileInfo) Sys() any           { return nil }

// ReadOnlyDirInfo returns a static fs.FileInfo for a read-only directory
func ReadOnlyDirInfo(name string) fs.FileInfo {
	return &StaticFileInfo{
		Named:    name,
		Sized:    0,
		Moded:    modeReadOnlyDir,
		ModTimed: time.Time{},
		Dir:      true,
	}
}
