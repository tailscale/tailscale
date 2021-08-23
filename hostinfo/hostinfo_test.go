// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hostinfo

import (
	"encoding/json"
	"testing"
)

func TestNew(t *testing.T) {
	hi := New()
	if hi == nil {
		t.Fatal("no Hostinfo")
	}
	j, err := json.MarshalIndent(hi, "  ", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %s", j)
}

func TestOSVersion(t *testing.T) {
	if osVersion == nil {
		t.Skip("not available for OS")
	}
	t.Logf("Got: %#q", osVersion())
}
