// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"reflect"
	"testing"
)

// Tests that [Config.Equal] tests all fields of [Config], even ones
// that might get added in the future.
func TestConfigEqual(t *testing.T) {
	rt := reflect.TypeFor[Config]()
	for sf := range rt.Fields() {
		switch sf.Name {
		case "Name", "NodeID", "PrivateKey", "Addresses":
			// These are compared in [Config.Equal].
		default:
			t.Errorf("Have you added field %q to Config.Equal? Do so if not, and then update TestConfigEqual", sf.Name)
		}
	}
}
