// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// BirthTime is not supported on Linux, so only run the test on windows and Mac.

//go:build windows || darwin

package driveimpl

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if err != nil {
		t.Fatalf("writing file failed: %s", err)
	}

	// wait a little bit
	time.Sleep(1 * time.Second)

	// append to the file to change its mtime
	file, err := os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("opening file failed: %s", err)
	}
	_, err = file.Write([]byte("lookin' good!"))
	if err != nil {
		t.Fatalf("appending to file failed: %s", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("closing file failed: %s", err)
	}

	checkFileInfo := func(fi os.FileInfo) {
		if fi.ModTime().IsZero() {
			t.Fatal("FileInfo should have a non-zero ModTime")
		}
		bt, ok := fi.(webdav.BirthTimer)
		if !ok {
			t.Fatal("FileInfo should be a BirthTimer")
		}
		birthTime, err := bt.BirthTime(ctx)
		if err != nil {
			t.Fatalf("BirthTime() failed: %s", err)
		}
		if birthTime.IsZero() {
			t.Fatal("BirthTime() should return a non-zero time")
		}
		if !fi.ModTime().After(birthTime) {
			t.Fatal("ModTime() should be after BirthTime()")
		}
	}

	fi, err := fs.Stat(ctx, filename)
	if err != nil {
		t.Fatalf("statting file failed: %s", err)
	}
	checkFileInfo(fi)

	wfile, err := fs.OpenFile(ctx, filename, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("opening file failed: %s", err)
	}
	defer wfile.Close()
	fi, err = wfile.Stat()
	if err != nil {
		t.Fatalf("statting file failed: %s", err)
	}
	if fi == nil {
		t.Fatal("statting file returned nil FileInfo")
	}
	checkFileInfo(fi)

	dfile, err := fs.OpenFile(ctx, ".", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("opening directory failed: %s", err)
	}
	defer dfile.Close()
	fis, err := dfile.Readdir(0)
	if err != nil {
		t.Fatalf("readdir failed: %s", err)
	}
	if len(fis) != 1 {
		t.Fatalf("readdir should have returned 1 file info, but returned %d", 1)
	}
	checkFileInfo(fis[0])
}
