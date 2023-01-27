// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package tstun

import (
	"os"

	"tailscale.com/types/logger"
)

func init() {
	tunDiagnoseFailure = diagnoseDarwinTUNFailure
}

func diagnoseDarwinTUNFailure(tunName string, logf logger.Logf, err error) {
	if os.Getuid() != 0 {
		logf("failed to create TUN device as non-root user; use 'sudo tailscaled', or run under launchd with 'sudo tailscaled install-system-daemon'")
	}
	if tunName != "utun" {
		logf("failed to create TUN device %q; try using tun device \"utun\" instead for automatic selection", tunName)
	}
}
