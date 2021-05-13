// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"io/ioutil"
	"os"
	"testing"

	"tailscale.com/tstest"
)

func TestFileStoreString(t *testing.T) {
	store := &FileStore{
		path: "foo",
	}
	expected := "FileStore(\"foo\")"
	if store.String() != expected {
		t.Errorf("FileStore.String(): got %q, want %q", store.String(), expected)
	}
}

func TestNewFileStore(t *testing.T) {
	tstest.PanicOnLog()

	f, err := ioutil.TempFile("", "test_ipn_store")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("creating file store failed: %v", err)
	}

	testStoreSemantics(t, store)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	store, err = NewFileStore(path)
	if err != nil {
		t.Fatalf("creating second file store failed: %v", err)
	}

	expected := map[StateKey]string{
		"foo": "bar",
		"baz": "quux",
	}
	for id, want := range expected {
		bs, err := store.ReadState(id)
		if err != nil {
			t.Errorf("reading %q (2nd store): %v", id, err)
		}
		if string(bs) != want {
			t.Errorf("reading %q (2nd store): got %q, want %q", id, string(bs), want)
		}
	}
}
