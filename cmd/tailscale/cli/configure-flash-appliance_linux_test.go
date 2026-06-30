// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import "testing"

func TestIsPartitionPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/dev/sda", false},
		{"/dev/sda1", true},
		{"/dev/sdb", false},
		{"/dev/sdb4", true},
		{"/dev/sdz9", true},
		{"/dev/vdb", false},
		{"/dev/vdb1", true},
		{"/dev/nvme0n1", false},
		{"/dev/nvme0n1p1", true},
		{"/dev/nvme0n1p4", true},
		{"/dev/mmcblk0", false},
		{"/dev/mmcblk0p1", true},
		{"/dev/loop0", false},
		{"/dev/loop0p1", true},
	}
	for _, tt := range tests {
		if got := isPartitionPath(tt.path); got != tt.want {
			t.Errorf("isPartitionPath(%q) = %v; want %v", tt.path, got, tt.want)
		}
	}
}
