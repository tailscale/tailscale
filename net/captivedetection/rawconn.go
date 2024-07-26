// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(ios || darwin)

package captivedetection

import (
	"syscall"

	"tailscale.com/types/logger"
)

// setSocketInterfaceIndex sets the IP_BOUND_IF socket option on the given RawConn.
// This forces the socket to use the given interface.
func setSocketInterfaceIndex(c syscall.RawConn, ifIndex int, logf logger.Logf) error {
	// No-op on non-Darwin platforms.
	return nil
}
