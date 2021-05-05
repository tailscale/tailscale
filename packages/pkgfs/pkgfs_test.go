// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgfs

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCreateOS(t *testing.T) {
	d, err := ioutil.TempDir("", "TestCreate")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(d)

	fname := "read-only-test"
	rfs := os.DirFS(d)
	if _, err := Create(rfs, fname, 0600); err == nil {
		t.Fatalf("Successfully created file in read-only FS")
	}

	fname = "write-test"
	wfs := DirFS(d)
	f, err := Create(wfs, fname, 0600)
	if err != nil {
		t.Fatalf("Couldn't create file: %v", err)
	}
	want := "test write"
	if _, err := f.Write([]byte(want)); err != nil {
		t.Fatalf("Writing to file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Closing created file: %v", err)
	}

	bs, err := ioutil.ReadFile(filepath.Join(d, fname))
	if err != nil {
		t.Fatalf("Opening written file %q: %v", fname, err)
	}

	got := string(bs)
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("Unexpected file contents (-got+want):\n%s", diff)
	}

	// When writing to the OS, the fs.FS should also read our writes.
	bs, err = fs.ReadFile(rfs, fname)
	if err != nil {
		t.Fatalf("Reading created file: %v", err)
	}
	got = string(bs)
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("Unexpected file contents (-got+want):\n%s", diff)
	}

	bs, err = fs.ReadFile(wfs, fname)
	if err != nil {
		t.Fatalf("Reading created file: %v", err)
	}
	got = string(bs)
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("Unexpected file contents (-got+want):\n%s", diff)
	}
}
