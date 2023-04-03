// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sysresources

// TotalMemory returns the total accessible system memory, in bytes. If the
// value cannot be determined, then 0 will be returned.
func TotalMemory() uint64 {
	return totalMemoryImpl()
}
