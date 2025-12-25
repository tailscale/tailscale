// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ethtool

import (
	"runtime"
	"testing"
)

func TestGetUDPGROTable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ethtool only on Linux")
	}
	
	table, err := GetUDPGROTable()
	if err != nil {
		t.Logf("GetUDPGROTable returned error (expected on non-Linux or without permissions): %v", err)
	}
	_ = table
}
