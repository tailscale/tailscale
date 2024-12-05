// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package tstun

import "github.com/tailscale/wireguard-go/tun"

func setLinkAttrs(iface tun.Device) error {
	return nil
}
