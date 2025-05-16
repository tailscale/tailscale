// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"maps"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

func TestNewStore(t *testing.T) {
	oldKnownStores := maps.Clone(knownStores)
	t.Cleanup(func() {
		knownStores = oldKnownStores
	})
	knownStores = map[string]Provider{}

	type store1 struct {
		ipn.StateStore
		path string
	}

	type store2 struct {
		ipn.StateStore
		path string
	}

	Register("arn:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return &store1{new(mem.Store), path}, nil
	})
	Register("kube:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return &store2{new(mem.Store), path}, nil
	})
	Register("mem:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return new(mem.Store), nil
	})

	path := "mem:abcd"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*mem.Store); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(mem.Store))
	}

	path = "arn:foo"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*store1); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(store1))
	}

	path = "kube:abcd"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*store2); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(store2))
	}

	path = filepath.Join(t.TempDir(), "state")
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*FileStore); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(FileStore))
	}
}

func testStoreSemantics(t *testing.T, store ipn.StateStore) {
	t.Helper()

	tests := []struct {
		// if true, data is data to write. If false, data is expected
		// output of read.
		write bool
		id    ipn.StateKey
		data  string
		// If write=false, true if we expect a not-exist error.
		notExists bool
	}{
		{
			id:        "foo",
			notExists: true,
		},
		{
			write: true,
			id:    "foo",
			data:  "bar",
		},
		{
			id:   "foo",
			data: "bar",
		},
		{
			id:        "baz",
			notExists: true,
		},
		{
			write: true,
			id:    "baz",
			data:  "quux",
		},
		{
			id:   "foo",
			data: "bar",
		},
		{
			id:   "baz",
			data: "quux",
		},
	}

	for _, test := range tests {
		if test.write {
			if err := store.WriteState(test.id, []byte(test.data)); err != nil {
				t.Errorf("writing %q to %q: %v", test.data, test.id, err)
			}
		} else {
			bs, err := store.ReadState(test.id)
			if err != nil {
				if test.notExists && err == ipn.ErrStateNotExist {
					continue
				}
				t.Errorf("reading %q: %v", test.id, err)
				continue
			}
			if string(bs) != test.data {
				t.Errorf("reading %q: got %q, want %q", test.id, string(bs), test.data)
			}
		}
	}
}

func TestMemoryStore(t *testing.T) {
	tstest.PanicOnLog()

	store := new(mem.Store)
	testStoreSemantics(t, store)
}

func TestFileStore(t *testing.T) {
	tstest.PanicOnLog()

	dir := t.TempDir()
	path := filepath.Join(dir, "test-file-store.conf")

	store, err := NewFileStore(nil, path)
	if err != nil {
		t.Fatalf("creating file store failed: %v", err)
	}

	testStoreSemantics(t, store)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	store, err = NewFileStore(nil, path)
	if err != nil {
		t.Fatalf("creating second file store failed: %v", err)
	}

	expected := map[ipn.StateKey]string{
		"foo": "bar",
		"baz": "quux",
	}
	for key, want := range expected {
		bs, err := store.ReadState(key)
		if err != nil {
			t.Errorf("reading %q (2nd store): %v", key, err)
			continue
		}
		if string(bs) != want {
			t.Errorf("reading %q (2nd store): got %q, want %q", key, bs, want)
		}
	}
}
