// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && go1.19

package main // import "tailscale.com/cmd/tailscaled"

func isWindowsService() bool { return false }

func runWindowsService() error { panic("unreachable") }

func beWindowsSubprocess() bool { return false }
