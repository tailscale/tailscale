// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && go1.19

package main // import "tailscale.com/cmd/tailscaled"

import (
	"tailscale.com/logpolicy"
	"tailscale.com/util/syspolicy/policyclient"
)

func isWindowsService() bool { return false }

func runWindowsService(polc policyclient.Client, pol *logpolicy.Policy) error { panic("unreachable") }

func beWindowsSubprocess() bool { return false }
