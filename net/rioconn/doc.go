// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"fmt"

	"github.com/tailscale/wireguard-go/conn/winrio"
)

// ErrRIOUnavailable is returned when Windows RIO is required but not available.
var ErrRIOUnavailable = fmt.Errorf("Registered I/O (RIO) is not available on this system")

// Initialize initializes the Windows RIO API extensions.
// It returns [ErrRIOUnavailable] if RIO cannot be used.
func Initialize() error {
	if !winrio.Initialize() {
		return ErrRIOUnavailable
	}
	return nil
}
