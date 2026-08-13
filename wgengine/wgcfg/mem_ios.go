// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"github.com/tailscale/wireguard-go/device"
)

func getDeviceOptions() []device.Option {
	// iOS has a very restrictive memory limit on network extensions.
	// Reduce the maximum amount of memory that wireguard-go can allocate
	// to avoid getting killed.
	return []device.Option{
		device.WithQueueStagedSize(64),
		device.WithQueueOutboundSize(64),
		device.WithQueueInboundSize(64),
		device.WithQueueHandshakeSize(64),
		device.WithPreallocatedBuffersPerPool(64),
	}
}
