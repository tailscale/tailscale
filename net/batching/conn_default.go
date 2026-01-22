// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package batching

import (
	"tailscale.com/types/nettype"
)

// tryUpgradeToConn is no-op on all platforms except linux.
func tryUpgradeToConn(pconn nettype.PacketConn, _ string, _ int) nettype.PacketConn {
	return pconn
}

var controlMessageSize = 0

func MinControlMessageSize() int {
	return controlMessageSize
}

const IdealBatchSize = 1
