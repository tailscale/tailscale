// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"testing"
)

func TestDefaultInterfacePortable(t *testing.T) {
	ifName, addr, err := DefaultInterfacePortable()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Default interface: %s", ifName)
	t.Logf("Default address: %s", addr)

	if ifName == "" {
		t.Fatal("Default interface name is empty")
	}
	if !addr.IsValid() {
		t.Fatal("Default address is invalid")
	}
}
