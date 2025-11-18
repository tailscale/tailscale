// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import "testing"

func TestConnector(t *testing.T) {
	c := &Connector{}
	if c == nil {
		t.Fatal("Connector is nil")
	}
}
