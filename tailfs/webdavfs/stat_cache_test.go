// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tailfs/shared"
	"tailscale.com/tstest"
)

func TestStatCache(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}

	// create file of size 1
	filename := filepath.Join(dir, "thefile")
	err = os.WriteFile(filename, []byte("1"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	stat := func(name string) (os.FileInfo, error) {
		return os.Stat(name)
	}
	ttl := 1 * time.Second
	c := newStatCache(ttl)

	// fetch new stat
	fi, err := c.getOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("got size %d, want 1", fi.Size())
	}
	// save original FileInfo as a StaticFileInfo so we can reuse it later
	// without worrying about the underlying FileInfo changing.
	originalFI := &shared.StaticFileInfo{
		Named:      fi.Name(),
		Sized:      fi.Size(),
		Moded:      fi.Mode(),
		ModdedTime: fi.ModTime(),
		Dir:        fi.IsDir(),
	}

	// update file to size 2
	err = os.WriteFile(filename, []byte("12"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// fetch stat again, should still be cached
	fi, err = c.getOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("got size %d, want 1", fi.Size())
	}

	// wait for cache to expire and refetch stat, size should reflect new size
	time.Sleep(ttl * 2)

	fi, err = c.getOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 2 {
		t.Errorf("got size %d, want 2", fi.Size())
	}

	// explicitly set the original FileInfo and make sure it's returned
	c.set(dir, []fs.FileInfo{originalFI})
	fi, err = c.getOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("got size %d, want 1", fi.Size())
	}

	// invalidate the cache and make sure the new size is returned
	c.invalidate()
	fi, err = c.getOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 2 {
		t.Errorf("got size %d, want 2", fi.Size())
	}

	c.stop()
}
