// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"
)

// iOS has a very restrictive memory limit on network extensions.
// Reduce the maximum amount of memory that wireguard-go can allocate
// to avoid getting killed.

func init() {
	device.QueueStagedSize = 64
	device.QueueOutboundSize = 64
	device.QueueInboundSize = 64
	device.QueueHandshakeSize = 64
	device.PreallocatedBuffersPerPool = 64
}
