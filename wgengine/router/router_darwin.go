// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	return newUserspaceBSDRouter(logf, wgdev, tundev)
}

// TODO(dmytro): the following should use a macOS-specific method such as scutil.
// This is currently not implemented. Editing /etc/resolv.conf does not work,
// as most applications use the system resolver, which disregards it.

func upDNS(DNSConfig, string) error { return nil }
func downDNS(string) error          { return nil }
func cleanup(logger.Logf, string)   {}
