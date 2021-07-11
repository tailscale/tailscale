// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnstate

import (
	"testing"

	"tailscale.com/tstest"
)

func TestMemoryStore(t *testing.T) {
	tstest.PanicOnLog()

	store := &MemoryStore{}
	testStoreSemantics(t, store)
}
