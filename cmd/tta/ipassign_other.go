// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package main

// startIPAssignLoop is a no-op on non-macOS platforms.
// macOS VMs use vsock-based IP assignment to bypass slow DHCP.
func startIPAssignLoop() {}

// Reference resetDialCancels to prevent unused-function lint errors.
// It's called from ipassign_darwin.go on macOS builds.
var _ = resetDialCancels
