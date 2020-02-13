// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/logger"
)

type darwinRouter struct {
	tunname string
}

func NewUserspaceRouter(logf logger.Logf, tunname string, dev *device.Device, tuntap tun.Device, netChanged func()) Router {
	r := darwinRouter{
		tunname: tunname,
	}
	return &r
}

func (r *darwinRouter) Up() error {
	return nil
}

func (r *darwinRouter) SetRoutes(rs RouteSettings) error {
	if SetRoutesFunc != nil {
		return SetRoutesFunc(rs)
	}
	return nil
}

func (r *darwinRouter) Close() error {
	return nil
}
