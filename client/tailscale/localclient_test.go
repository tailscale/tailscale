// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19

package tailscale

import "testing"

func TestGetServeConfigFromJSON(t *testing.T) {
	sc, err := getServeConfigFromJSON([]byte("null"))
	if sc != nil {
		t.Errorf("want nil for null")
	}
	if err != nil {
		t.Errorf("reading null: %v", err)
	}

	sc, err = getServeConfigFromJSON([]byte(`{"TCP":{}}`))
	if err != nil {
		t.Errorf("reading object: %v", err)
	} else if sc == nil {
		t.Errorf("want non-nil for object")
	} else if sc.TCP == nil {
		t.Errorf("want non-nil TCP for object")
	}
}
