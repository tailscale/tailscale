// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import "syscall"

// bypassControlFunc is a no-op on non-Linux platforms; SO_MARK is a Linux
// concept and exit-node routing only matters here for Linux VMs in vmtest.
func bypassControlFunc(network, address string, c syscall.RawConn) error {
	return nil
}
