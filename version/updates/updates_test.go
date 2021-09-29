// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package updates

import (
	"bytes"
	"os"
	"testing"

	"github.com/tailscale/hujson"
)

func TestParse(t *testing.T) {
	rulesJSON, err := os.ReadFile("rules.json")
	if err != nil {
		t.Fatal(err)
	}

	d := hujson.NewDecoder(bytes.NewReader(rulesJSON))
	d.DisallowUnknownFields()

	var p Policy
	if err := d.Decode(&p); err != nil {
		t.Fatal(err)
	}
}
