// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || windows || darwin || freebsd

package safesocket

import (
	"strings"

	ps "github.com/mitchellh/go-ps"
)

func init() {
	tailscaledProcExists = func() bool {
		procs, err := ps.Processes()
		if err != nil {
			return false
		}
		for _, proc := range procs {
			name := proc.Executable()
			const tailscaled = "tailscaled"
			if len(name) < len(tailscaled) {
				continue
			}
			// Do case insensitive comparison for Windows,
			// notably, and ignore any ".exe" suffix.
			if strings.EqualFold(name[:len(tailscaled)], tailscaled) {
				return true
			}
		}
		return false
	}
}
