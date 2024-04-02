// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package shared

import (
	"context"
	"io/fs"
	"os"
	"time"

	"github.com/tailscale/xnet/webdav"
)

// StaticFileInfo implements a static fs.FileInfo
type StaticFileInfo struct {
	// Named controls Name()
	Named string
	// Sized controls Size()
	Sized int64
	// Moded controls Mode()
	Moded os.FileMode
	// BirthedTime controls BirthTime()
	BirthedTime time.Time
	// BirthedTimeErr stores any error encountered when trying to get BirthTime
	BirthedTimeErr error
	// ModdedTime controls ModTime()
	ModdedTime time.Time
	// Dir controls IsDir()
	Dir bool
}

// BirthTime implements webdav.BirthTimer
func (fi *StaticFileInfo) BirthTime(_ context.Context) (time.Time, error) {
	return fi.BirthedTime, fi.BirthedTimeErr
}
func (fi *StaticFileInfo) Name() string       { return fi.Named }
func (fi *StaticFileInfo) Size() int64        { return fi.Sized }
func (fi *StaticFileInfo) Mode() os.FileMode  { return fi.Moded }
func (fi *StaticFileInfo) ModTime() time.Time { return fi.ModdedTime }
func (fi *StaticFileInfo) IsDir() bool        { return fi.Dir }
func (fi *StaticFileInfo) Sys() any           { return nil }

func RenamedFileInfo(ctx context.Context, name string, fi fs.FileInfo) *StaticFileInfo {
	var birthTime time.Time
	var birthTimeErr error
	birthTimer, ok := fi.(webdav.BirthTimer)
	if ok {
		birthTime, birthTimeErr = birthTimer.BirthTime(ctx)
	}

	return &StaticFileInfo{
		Named:          Base(name),
		Sized:          fi.Size(),
		Moded:          fi.Mode(),
		BirthedTime:    birthTime,
		BirthedTimeErr: birthTimeErr,
		ModdedTime:     fi.ModTime(),
		Dir:            fi.IsDir(),
	}
}

// ReadOnlyDirInfo returns a static fs.FileInfo for a read-only directory
func ReadOnlyDirInfo(name string, ts time.Time) *StaticFileInfo {
	return &StaticFileInfo{
		Named:       Base(name),
		Sized:       0,
		Moded:       0555,
		BirthedTime: ts,
		ModdedTime:  ts,
		Dir:         true,
	}
}
