// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package vcstime provides a file system wrapper that gives embedded
// files a meaningful modification time.
//
// embed.FS stores and serves no ModTime: files report a zero
// [fs.FileInfo.ModTime], which disables HTTP caching semantics when
// served with [net/http]: no Last-Modified header is sent and
// If-Modified-Since requests are never answered with a 304. vcstime
// derives a modification time from the vcs.time build setting recorded
// by the go command (see "go version -m" or [debug.BuildInfo]),
// enabling [http.FS] to provide working cache headers for clean builds.
//
// FS wraps an [fs.FS] (typically an [embed.FS]) and reports that time as
// the modification time of every file that does not have a real
// timestamp of its own. Usage:
//
//	//go:embed internal/whatever/*.*
//	var content embed.FS
//
//	mux.Handle("/", http.FileServer(http.FS(vcstime.FS(content))))
//
// vcs.time is the commit time of the revision that was built, not the
// wall-clock build time: the two coincide for clean CI builds, but a
// tree with local modifications yields an older commit time. Binaries
// built without VCS stamping (for example with -buildvcs=false) have no
// vcs.time, and FS then behaves exactly like the file system it wraps.
package vcstime

import (
	"io"
	"io/fs"
	"runtime/debug"
	"sync"
	"time"
)

var (
	vcsTimeOnce sync.Once
	vcsTimeVal  time.Time
)

// ModTime returns the modification time reported for timestamp-less files
// by file systems created with FS: the vcs.time commit time of the
// running binary's source revision, or the zero time if the binary
// carries no VCS build stamp.
func ModTime() time.Time {
	vcsTimeOnce.Do(func() {
		bi, ok := debug.ReadBuildInfo()
		if ok {
			vcsTimeVal = vcsTime(bi)
		}
	})
	return vcsTimeVal
}

// vcsTime returns the vcs.time build setting from bi as a time, or the
// zero time if it is absent or unparseable.
func vcsTime(bi *debug.BuildInfo) time.Time {
	for _, s := range bi.Settings {
		if s.Key != "vcs.time" {
			continue
		}
		t, err := time.Parse(time.RFC3339, s.Value)
		if err != nil {
			return time.Time{}
		}
		return t
	}
	return time.Time{}
}

// FS returns an [fs.FS] that serves files from fsys, reporting [ModTime]
// as the modification time of any file that has no real timestamp of its
// own.
//
// It is intended for wrapping an [embed.FS], whose files always report a
// zero ModTime. Files that already have a real timestamp (for example in
// an [fstest.MapFS] or os-backed file system) are passed through
// unchanged, so it is always safe to wrap.
//
// If the binary carries no vcs.time stamp, fsys itself is returned
// unchanged.
func FS(fsys fs.FS) fs.FS {
	return New(fsys, ModTime())
}

// New is like FS, but with an explicit modification time to report for
// files that have none of their own. If mod is the zero time, fsys is
// returned unchanged.
//
// This exists mostly for tests; prefer FS in production code.
func New(fsys fs.FS, mod time.Time) fs.FS {
	if fsys == nil || mod.IsZero() {
		return fsys
	}
	return &modFS{fsys: fsys, mod: mod}
}

// modFS is an fs.FS wrapper that stamps timestamp-less files with a fixed
// modification time.
type modFS struct {
	fsys fs.FS
	mod  time.Time
}

var (
	_ fs.ReadDirFS  = (*modFS)(nil)
	_ fs.ReadFileFS = (*modFS)(nil)
)

func (m *modFS) Open(name string) (fs.File, error) {
	f, err := m.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	return &modFile{File: f, name: name, mod: m.mod}, nil
}

func (m *modFS) ReadDir(name string) ([]fs.DirEntry, error) {
	des, err := fs.ReadDir(m.fsys, name)
	return stampDirEntries(des, m.mod), err
}

func (m *modFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(m.fsys, name)
}

// modFile is an fs.File wrapper that reports a stamped modification time
// from Stat. Read, Close, Seek and ReadDir are forwarded to the
// underlying file when it supports them, so that http.FS and other
// consumers keep working (http.FS type-asserts files for io.Seeker and
// fs.ReadDirFile).
type modFile struct {
	fs.File
	name string
	mod  time.Time
}

var _ fs.ReadDirFile = (*modFile)(nil)

func (f *modFile) Stat() (fs.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return stampFileInfo(info, f.mod), nil
}

func (f *modFile) Seek(offset int64, whence int) (int64, error) {
	if s, ok := f.File.(io.Seeker); ok {
		return s.Seek(offset, whence)
	}
	return 0, &fs.PathError{Op: "seek", Path: f.name, Err: fs.ErrInvalid}
}

func (f *modFile) ReadDir(n int) ([]fs.DirEntry, error) {
	rdf, ok := f.File.(fs.ReadDirFile)
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: f.name, Err: fs.ErrInvalid}
	}
	des, err := rdf.ReadDir(n)
	return stampDirEntries(des, f.mod), err
}

// stampFileInfo returns info unchanged if it already has a modification
// time or there is nothing to stamp it with, and otherwise a FileInfo
// that reports mod instead.
func stampFileInfo(info fs.FileInfo, mod time.Time) fs.FileInfo {
	if mod.IsZero() || !info.ModTime().IsZero() {
		return info
	}
	return modFileInfo{FileInfo: info, mod: mod}
}

func stampDirEntries(des []fs.DirEntry, mod time.Time) []fs.DirEntry {
	if mod.IsZero() {
		return des
	}
	for i, de := range des {
		info, err := de.Info()
		if err != nil {
			continue
		}
		if info.ModTime().IsZero() {
			des[i] = fs.FileInfoToDirEntry(modFileInfo{FileInfo: info, mod: mod})
		}
	}
	return des
}

// modFileInfo is an fs.FileInfo that reports mod as its modification
// time, delegating everything else.
type modFileInfo struct {
	fs.FileInfo
	mod time.Time
}

func (i modFileInfo) ModTime() time.Time { return i.mod }
