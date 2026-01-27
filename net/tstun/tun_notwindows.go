// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package tstun

import "github.com/tailscale/wireguard-go/tun"

func interfaceName(dev tun.Device) (string, error) {
	return dev.Name()
}
