// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"testing"

	"tailscale.com/tstest"
)

func TestMemoryStoreString(t *testing.T) {
	store := &MemoryStore{}
	if store.String() != "MemoryStore" {
		t.Errorf("MemoryStore.String(): got %q, want %q", store.String(), "MemoryStore")
	}
}

func TestMemoryStore(t *testing.T) {
	tstest.PanicOnLog()

	store := &MemoryStore{}
	testStoreSemantics(t, store)
}
