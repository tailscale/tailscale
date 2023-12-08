// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatCache(t *testing.T) {
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
	ttl := 250 * time.Millisecond
	c := newStatCache(ttl)

	// fetch new stat
	fi, err := c.GetOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("got size %d, want 1", fi.Size())
	}

	// update file to size 2
	err = os.WriteFile(filename, []byte("12"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// fetch stat again, should still be cached
	fi, err = c.GetOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("got size %d, want 1", fi.Size())
	}

	// wait for cache to expire and refetch stat, size should reflect new size
	time.Sleep(ttl)

	fi, err = c.GetOrFetch(filename, stat)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 2 {
		t.Errorf("got size %d, want 2", fi.Size())
	}
}
