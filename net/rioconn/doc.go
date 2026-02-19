// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// Package rioconn provides [UDPConn], a UDP socket implementation
// that uses the Windows RIO API extensions and supports batched I/O,
// USO and URO for improved performance on high-throughput UDP workloads.
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
