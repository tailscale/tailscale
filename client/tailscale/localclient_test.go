// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

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

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			// Make sure we don't again accidentally bring in a dependency on
			// TailFS or its transitive dependencies
			"tailscale.com/tailfs/tailfsimpl": "https://github.com/tailscale/tailscale/pull/10631",
			"github.com/studio-b12/gowebdav":  "https://github.com/tailscale/tailscale/pull/10631",
		},
	}.Check(t)
}
