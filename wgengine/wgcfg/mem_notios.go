// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package wgcfg

import "github.com/tailscale/wireguard-go/device"

func getDeviceOptions() []device.Option {
	// Return nothing in order to use wireguard-go defaults, e.g. [device.DefaultQueueOutboundSize].
	return nil
}
