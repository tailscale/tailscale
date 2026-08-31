// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"github.com/tailscale/wireguard-go/device"
)

func getDeviceOptions() []device.Option {
	// iOS has a very restrictive memory limit on network extensions.
	// Reduce the maximum amount of memory that wireguard-go can allocate to
	// avoid getting killed.
	//
	// See _notios.go for a longer explanation of what the Queue{In,Out}boundSize
	// knobs control and the tradeoffs involved. Eventually Queue{In,Out}boundSize
	// should be CPU-scaled, and WithPreallocated... removed, but we keep them all
	// static for now, until the [device.WaitPool] ceiling is eliminated.
	// (See tailscale/corp#46396).
	return []device.Option{
		device.WithQueueStagedSize(64),
		device.WithQueueOutboundSize(64),
		device.WithQueueInboundSize(64),
		device.WithQueueHandshakeSize(64),
		device.WithPreallocatedBuffersPerPool(64),
	}
}
