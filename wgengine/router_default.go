// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!linux,!darwin,!openbsd,!freebsd

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

const DefaultTunName = "tailscale0"

func newUserspaceRouter(logf logger.Logf, tunname string, dev *device.Device, tuntap tun.Device, netChanged func()) Router {
	return NewFakeRouter(logf, tunname, dev, tuntap, netChanged)
}
