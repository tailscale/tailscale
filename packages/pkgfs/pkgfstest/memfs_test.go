// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgfstest

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"tailscale.com/packages/pkgfs"
)

func TestMapFS(t *testing.T) {
	fsys := MapFS{
		"read": &fstest.MapFile{
			Data: []byte("read"),
			Mode: 0600,
		},
	}

	if err := fstest.TestFS(fsys, "read"); err != nil {
		t.Fatal(err)
	}

	f, err := pkgfs.Create(fsys, "write", 0654)
	if err != nil {
		t.Fatalf("Creating file: %v", err)
	}

	st, err := fs.Stat(fsys, "write")
	if err != nil {
		t.Fatalf("Stat of created file: %v", err)
	}
	if st.Mode().Perm() != 0654 {
		t.Fatalf("Wrong permissions on created file: got %o, want %o", st.Mode().Perm(), 0654)
	}

	data := "test content\n"
	n, err := f.Write([]byte(data))
	if err != nil {
		t.Fatalf("Writing test file: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Short write: got %d bytes, want %d", n, len(data))
	}

	// The file can be concurrently read, as long as the reads and
	// writes are serialized.
	bs, err := fs.ReadFile(fsys, "write")
	if err != nil {
		t.Fatalf("Reading created file: %v", err)
	}
	got := string(bs)
	if got != data {
		t.Fatalf("Written file has wrong content, got %q, want %q", got, data)
	}

	n, err = f.Write([]byte(data))
	if err != nil {
		t.Fatalf("Writing test file: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Short write: got %d bytes, want %d", n, len(data))
	}

	bs, err = fs.ReadFile(fsys, "write")
	if err != nil {
		t.Fatalf("Reading created file: %v", err)
	}
	got = string(bs)
	if got != data+data {
		t.Fatalf("Written file has wrong content, got %q, want %q", got, data+data)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Closing file: %v", err)
	}

	bs, err = fs.ReadFile(fsys, "write")
	if err != nil {
		t.Fatalf("Reading created file: %v", err)
	}
	got = string(bs)
	if got != data+data {
		t.Fatalf("Written file has wrong content, got %q, want %q", got, data+data)
	}

	if err := fstest.TestFS(fsys, "read", "write"); err != nil {
		t.Fatal(err)
	}
}
