// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"testing"
)

func testStoreSemantics(t *testing.T, store StateStore) {
	t.Helper()

	tests := []struct {
		// if true, data is data to write. If false, data is expected
		// output of read.
		write bool
		id    StateKey
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
				if test.notExists && err == ErrStateNotExist {
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
