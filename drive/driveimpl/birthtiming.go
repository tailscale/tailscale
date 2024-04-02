// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"context"
	"io/fs"
	"os"
	"time"

	"github.com/djherbis/times"
	"github.com/tailscale/xnet/webdav"
)

// birthTimingFS extends a webdav.FileSystem to return FileInfos that implement
// the webdav.BirthTimer interface.
type birthTimingFS struct {
	webdav.FileSystem
}

func (fs *birthTimingFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, err := fs.FileSystem.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	return &birthTimingFileInfo{fi}, nil
}

func (fs *birthTimingFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	f, err := fs.FileSystem.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}

	return &birthTimingFile{f}, nil
}

// birthTimingFileInfo extends an os.FileInfo to implement the BirthTimer
// interface.
type birthTimingFileInfo struct {
	os.FileInfo
}

func (fi *birthTimingFileInfo) BirthTime(ctx context.Context) (time.Time, error) {
	if fi.Sys() == nil {
		return time.Time{}, webdav.ErrNotImplemented
	}

	if !times.HasBirthTime {
		return time.Time{}, webdav.ErrNotImplemented
	}

	return times.Get(fi.FileInfo).BirthTime(), nil
}

// birthTimingFile extends a webdav.File to return FileInfos that implement the
// BirthTimer interface.
type birthTimingFile struct {
	webdav.File
}

func (f *birthTimingFile) Stat() (fs.FileInfo, error) {
	fi, err := f.File.Stat()
	if err != nil {
		return nil, err
	}

	return &birthTimingFileInfo{fi}, nil
}

func (f *birthTimingFile) Readdir(count int) ([]fs.FileInfo, error) {
	fis, err := f.File.Readdir(count)
	if err != nil {
		return nil, err
	}

	for i, fi := range fis {
		fis[i] = &birthTimingFileInfo{fi}
	}

	return fis, nil
}
