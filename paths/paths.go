// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package paths returns platform and user-specific default paths to
// Tailscale files and directories.
package paths

import (
	"os"
	"runtime"
)

// LegacyConfigPath is the path used by the pre-tailscaled "relaynode"
// daemon's config file.
const LegacyConfigPath = "/var/lib/tailscale/relay.conf"

// DefaultTailscaledSocket returns the path to the tailscaled Unix socket
// or the empty string if there's no reasonable default.
func DefaultTailscaledSocket() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if fi, err := os.Stat("/var/run"); err == nil && fi.IsDir() {
		return "/var/run/tailscale/tailscaled.sock"
	}
	return "tailscaled.sock"
}

var stateFileFunc func() string

// DefaultTailscaledStateFile returns the default path to the
// tailscaled state file, or the empty string if there's no reasonable
// default value.
func DefaultTailscaledStateFile() string {
	if f := stateFileFunc; f != nil {
		return f()
	}
	return ""
}
