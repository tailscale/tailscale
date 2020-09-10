// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstat

import (
	"testing"
)

func TestGet(t *testing.T) {
	nt, err := Get()
	if err == ErrNotImplemented {
		t.Skip("TODO: not implemented")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range nt.Entries {
		t.Logf("Entry: %+v", e)
	}
}
