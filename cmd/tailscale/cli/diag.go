// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || windows || darwin
// +build linux windows darwin

package cli

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	ps "github.com/mitchellh/go-ps"
)

// fixTailscaledConnectError is called when the local tailscaled has
// been determined unreachable due to the provided origErr value. It
// returns either the same error or a better one to help the user
// understand why tailscaled isn't running for their platform.
func fixTailscaledConnectError(origErr error) error {
	procs, err := ps.Processes()
	if err != nil {
		return fmt.Errorf("failed to connect to local Tailscaled process and failed to enumerate processes while looking for it")
	}
	found := false
	for _, proc := range procs {
		base := filepath.Base(proc.Executable())
		if base == "tailscaled" {
			found = true
			break
		}
		if runtime.GOOS == "darwin" && base == "IPNExtension" {
			found = true
			break
		}
		if runtime.GOOS == "windows" && strings.EqualFold(base, "tailscaled.exe") {
			found = true
			break
		}
	}
	if !found {
		switch runtime.GOOS {
		case "windows":
			return fmt.Errorf("failed to connect to local tailscaled process; is the Tailscale service running?")
		case "darwin":
			return fmt.Errorf("failed to connect to local Tailscale service; is Tailscale running?")
		case "linux":
			return fmt.Errorf("failed to connect to local tailscaled; it doesn't appear to be running (sudo systemctl start tailscaled ?)")
		}
		return fmt.Errorf("failed to connect to local tailscaled process; it doesn't appear to be running")
	}
	return fmt.Errorf("failed to connect to local tailscaled (which appears to be running). Got error: %w", origErr)
}
