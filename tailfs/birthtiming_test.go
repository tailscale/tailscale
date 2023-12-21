// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// BirthTime is not supported on Linux, so only run the test on windows and Mac.

//go:build windows || darwin

package tailfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/tailscale/xnet/webdav"
)

func TestBirthTiming(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	fs := &birthTimingFS{webdav.Dir(dir)}

	// create a file
	filename := "thefile"
	fullPath := filepath.Join(dir, filename)
	err := os.WriteFile(fullPath, []byte("hello beautiful world"), 0644)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("writing file should succeed"))

	// wait a little bit
	time.Sleep(1 * time.Second)

	// append to the file to change its mtime
	file, err := os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY, 0644)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("opening file should succeed"))
	_, err = file.Write([]byte("lookin' good!"))
	qt.Assert(t, err, qt.IsNil, qt.Commentf("appending to file should succeed"))
	err = file.Close()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("closing file should succeed"))

	checkFileInfo := func(fi os.FileInfo) {
		qt.Assert(t, fi.ModTime().IsZero(), qt.IsFalse, qt.Commentf("FileInfo should have a non-zero ModTime"))
		qt.Assert(t, fi.ModTime().IsZero(), qt.IsFalse, qt.Commentf("statting file should return a non-zero ModTime"))
		bt, ok := fi.(webdav.BirthTimer)
		qt.Assert(t, ok, qt.IsTrue, qt.Commentf("FileInfo should be a BirthTimer"))
		birthTime, err := bt.BirthTime(ctx)
		qt.Assert(t, err, qt.IsNil, qt.Commentf("BirthTime() should succeed"))
		qt.Assert(t, birthTime.IsZero(), qt.IsFalse, qt.Commentf("BirthTime() should return a non-zero time"))
		qt.Assert(t, fi.ModTime().After(birthTime), qt.IsTrue, qt.Commentf("ModTime() should be after BirthTime()"))
	}

	fi, err := fs.Stat(ctx, filename)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("statting file should succeed"))
	qt.Assert(t, fi, qt.IsNotNil, qt.Commentf("statting file should return a non-nil FileInfo"))
	checkFileInfo(fi)

	wfile, err := fs.OpenFile(ctx, filename, os.O_RDONLY, 0)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("opening file should succeed"))
	defer wfile.Close()
	fi, err = wfile.Stat()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("statting file should succeed"))
	qt.Assert(t, fi, qt.IsNotNil, qt.Commentf("statting file should return a non-nil FileInfo"))
	checkFileInfo(fi)

	dfile, err := fs.OpenFile(ctx, ".", os.O_RDONLY, 0)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("opening directory should succeed"))
	defer dfile.Close()
	fis, err := dfile.Readdir(0)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("readdir should succeed"))
	qt.Assert(t, len(fis), qt.Equals, 1, qt.Commentf("readdir should return one FileInfo"))
	checkFileInfo(fis[0])
}
