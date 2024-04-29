// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/envknob"
)

func setLinkFeatures(dev tun.Device) error {
	if envknob.Bool("TS_TUN_DISABLE_UDP_GRO") {
		linuxDev, ok := dev.(tun.LinuxDevice)
		if ok {
			linuxDev.DisableUDPGRO()
		}
	}
	return nil
}
