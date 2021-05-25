// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!linux,!darwin,!openbsd,!freebsd

package router

import (
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, tunname string, tunDev tun.Device, netChanged func()) Router {
	return NewFakeRouter(logf, tunname, tunDev, netChanged)
}

func cleanup(logf logger.Logf, interfaceName string) {
	// Nothing to do here.
}
